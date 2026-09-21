"""Elasticsearch sink for guardrail verdicts.

Spark-free, like the Jev client, so the mapping and the bulk path can be
exercised from a REPL without starting a SparkSession.

Documents are indexed with _id = event_id. That makes every write idempotent:
if Spark reprocesses a Kafka offset after a restart, the verdict is overwritten
in place rather than duplicated. An audit store that double-counts under
recovery is worse than no audit store, because it looks right.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any, Final, Iterable

from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk

from pydantic import BaseModel, ConfigDict
from src.config import get_settings

logger = logging.getLogger(__name__)

# dynamic: "strict" rejects any field not declared below.
#
# The default -- dynamic mapping -- infers a type from the first document that
# contains a field. That is how clusters die: one stray key per event creates
# one field per event, the mapping grows without bound, and the cluster state
# eventually stops fitting in memory. It is called mapping explosion and it is
# the single most common self-inflicted Elasticsearch outage. Strict mode turns
# a silent schema drift into a loud rejection at write time.
INDEX_MAPPING: Final[dict[str, Any]] = {
    "dynamic": "strict",
    "properties": {
        # --- identity / time ------------------------------------------------
        "event_id": {"type": "keyword"},
        "trace_id": {"type": "keyword"},
        "schema_version": {"type": "keyword"},
        "event_timestamp": {"type": "date"},
        "ingested_at": {"type": "date"},
        "ingest_lag_ms": {"type": "long"},

        # --- agent ----------------------------------------------------------
        "agent": {
            "properties": {
                "agent_id": {"type": "keyword"},
                "agent_name": {"type": "keyword"},
                "session_id": {"type": "keyword"},
                "tenant_id": {"type": "keyword"},
                "llm_provider": {"type": "keyword"},
                "llm_model": {"type": "keyword"},
            }
        },

        # --- action ---------------------------------------------------------
        "action_type": {"type": "keyword"},
        # Dual-mapped on purpose. `text` is analysed into terms so RAG and
        # free-text search work ("find actions mentioning credentials").
        # `.keyword` keeps the exact string for aggregations and dedup.
        # ignore_above skips indexing the keyword form for very long commands,
        # which prevents oversized terms without losing the text index.
        "raw_command": {
            "type": "text",
            "fields": {"keyword": {"type": "keyword", "ignore_above": 1024}},
        },
        "target_resource": {
            "type": "text",
            "fields": {"keyword": {"type": "keyword", "ignore_above": 512}},
        },
        "requested_privilege": {"type": "keyword"},
        # `flattened` is the correct answer for genuinely open-ended key/value
        # data: the whole object is indexed as one field, so N distinct keys
        # cost 1 mapping entry instead of N. This is the ONE place we allow
        # unknown keys, and flattened is why it's safe.
        "parameters": {"type": "flattened"},

        # --- verdict ----------------------------------------------------------
        "verdict": {"type": "keyword"},
        "label": {"type": "keyword"},
        "confidence": {"type": "float"},
        "unsafe_mass": {"type": "float"},
        # Explicit sub-fields, not flattened: we own this label set, so a new
        # label should fail the strict mapping and make us think about it.
        "probabilities": {
            "properties": {
                "safe": {"type": "float"},
                "destructive": {"type": "float"},
                "exfiltration": {"type": "float"},
                "jailbreak": {"type": "float"},
            }
        },
        "reason": {"type": "text"},
        "tripwire": {"type": "keyword"},
        "degraded": {"type": "boolean"},

        # --- operational ------------------------------------------------------
        "latency_ms": {"type": "float"},
        "cost_usd": {"type": "double"},
        "batch_id": {"type": "long"},
        # Evaluation only. Indexed so Step 4B can score precision/recall.
        # The interceptor still never reads it.
        "source": {"type": "keyword"},
    },
}

INDEX_SETTINGS: Final[dict[str, Any]] = {
    # Single node locally: 1 shard, 0 replicas. A replica with nowhere to go
    # leaves the index permanently yellow and confuses everyone who looks.
    "number_of_shards": 1,
    "number_of_replicas": 0,
    "refresh_interval": "1s",
}


@lru_cache(maxsize=1)
def get_client() -> Elasticsearch:
    """One cached client per process. Supports Elastic Cloud or a local node."""
    settings = get_settings()

    common: dict[str, Any] = {
        "request_timeout": settings.elastic_bulk_timeout,
        "retry_on_timeout": True,
        "max_retries": 3,
    }

    if settings.elastic_cloud_id:
        logger.info("Connecting to Elastic Cloud")
        return Elasticsearch(
            cloud_id=settings.elastic_cloud_id,
            api_key=settings.elastic_api_key,
            **common,
        )

    logger.info("Connecting to Elasticsearch at %s", settings.elastic_hosts)
    auth: dict[str, Any] = {}
    if settings.elastic_api_key:
        auth["api_key"] = settings.elastic_api_key
    elif settings.elastic_username and settings.elastic_password:
        auth["basic_auth"] = (settings.elastic_username, settings.elastic_password)

    return Elasticsearch(
        hosts=[settings.elastic_hosts],
        verify_certs=settings.elastic_verify_certs,
        ssl_show_warn=settings.elastic_verify_certs,
        **auth,
        **common,
    )


def ensure_index() -> None:
    """Create the verdict index with an explicit mapping. Safe to call repeatedly."""
    settings = get_settings()
    client = get_client()
    index = settings.elastic_index_verdicts

    if client.indices.exists(index=index):
        logger.info("Index '%s' already exists", index)
        return

    try:
        client.indices.create(index=index, mappings=INDEX_MAPPING, settings=INDEX_SETTINGS)
        logger.info("Created index '%s'", index)
    except Exception as exc:  # concurrent creation is fine
        if "resource_already_exists_exception" in str(exc):
            logger.info("Index '%s' created concurrently", index)
            return
        raise


def build_document(row: Any, batch_id: int) -> dict[str, Any]:
    """Map one Spark Row to an Elasticsearch document.

    Written defensively: streaming rows can carry nulls in any field, and a
    KeyError here would kill the whole micro-batch.
    """
    now = datetime.now(timezone.utc)
    assessment = row["a"] or {}
    agent = row["agent"] or {}
    payload = row["payload"] or {}

    event_ts = row["event_timestamp"]
    lag_ms: int | None = None
    if isinstance(event_ts, str):
        try:
            parsed = datetime.fromisoformat(event_ts)
            lag_ms = int((now - parsed).total_seconds() * 1000)
        except ValueError:
            lag_ms = None

    params = payload.get("parameters") or {}

    return {
        "_op_type": "index",
        "_index": get_settings().elastic_index_verdicts,
        "_id": row["event_id"],          # idempotency key
        "_source": {
            "event_id": row["event_id"],
            "trace_id": row["trace_id"],
            "schema_version": row["schema_version"],
            "event_timestamp": event_ts,
            "ingested_at": now.isoformat(),
            "ingest_lag_ms": lag_ms,
            "agent": {
                "agent_id": agent.get("agent_id"),
                "agent_name": agent.get("agent_name"),
                "session_id": agent.get("session_id"),
                "tenant_id": agent.get("tenant_id"),
                "llm_provider": agent.get("llm_provider"),
                "llm_model": agent.get("llm_model"),
            },
            "action_type": row["action_type"],
            "raw_command": payload.get("raw_command"),
            "target_resource": payload.get("target_resource"),
            "requested_privilege": payload.get("requested_privilege"),
            "parameters": dict(params),
            "verdict": assessment.get("verdict"),
            "label": assessment.get("label"),
            "confidence": assessment.get("confidence"),
            "unsafe_mass": assessment.get("unsafe_mass"),
            "probabilities": dict(assessment.get("probabilities") or {}),
            "reason": assessment.get("reason"),
            "tripwire": row["tripwire"],
            "degraded": assessment.get("degraded"),
            "latency_ms": assessment.get("latency_ms"),
            "cost_usd": assessment.get("cost_usd"),
            "batch_id": batch_id,
            "source": row["source"],
        },
    }


class BulkFailure(BaseModel):
    """One document Elasticsearch refused, with enough detail to route it."""

    model_config = ConfigDict(frozen=True)

    event_id: str | None
    status: int
    error_type: str
    reason: str

    @property
    def retryable(self) -> bool:
        # 429 = back-pressure and 5xx = server trouble: the same document may
        # succeed later. 4xx = the document itself is wrong and will fail
        # identically forever. Unknown (0) counts as retryable: a retryable
        # letter can always be discarded later; a discarded one can't be retried.
        return self.status in (0, 429) or self.status >= 500


def _parse_bulk_error(item: dict[str, Any]) -> BulkFailure:
    operation = next(iter(item.values()), {}) if item else {}
    error = operation.get("error") or {}
    if not isinstance(error, dict):
        error = {"type": "unknown", "reason": str(error)}
    return BulkFailure(
        event_id=operation.get("_id"),
        status=int(operation.get("status") or 0),
        error_type=str(error.get("type", "unknown")),
        reason=str(error.get("reason", ""))[:1000],
    )


def index_documents(documents: Iterable[dict[str, Any]]) -> tuple[int, list[BulkFailure]]:
    """Bulk-index. Returns (succeeded, per-document failures).

    Per-document rejections are RETURNED so the caller can dead-letter them.
    Transport failures (cluster unreachable, auth) still RAISE: that's an
    outage, not a bad document, and the right response is to fail the batch
    and let Spark replay it from the checkpoint.
    """
    docs = list(documents)
    if not docs:
        return 0, []
    succeeded, errors = bulk(
        get_client(),
        docs,
        raise_on_error=False,     # per-document failures come back as data
        raise_on_exception=True,  # transport failures propagate
        stats_only=False,
        request_timeout=get_settings().elastic_bulk_timeout,
    )
    failures = [_parse_bulk_error(e) for e in errors] if isinstance(errors, list) else []
    for failure in failures[:5]:
        logger.error("Bulk rejection id=%s status=%d %s: %s",
                     failure.event_id, failure.status, failure.error_type, failure.reason)
    return succeeded, failures

