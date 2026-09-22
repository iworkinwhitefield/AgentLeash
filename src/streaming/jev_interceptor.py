""" 
PySpark Structured Streaming interceptor.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from typing import Final
import threading

import pandas as pd
import pyspark
from pyspark.sql import DataFrame, SparkSession
from pyspark.sql import functions as F
from pyspark.sql.functions import pandas_udf
from pyspark.sql.types import (
    BooleanType,
    DoubleType,
    MapType,
    StringType,
    StructField,
    StructType,
)

from src.config import get_settings
from src.decisions.jev_client import RiskAssessment, Verdict, assess_action
from src.sinks.elastic_sink import build_document, ensure_index, index_documents

from collections import Counter
from typing import Callable

from pyspark.sql import Column, Row

from src.dlq.dead_letter import (
    ATTEMPT_HEADER, DeadLetterContext, DLQStage, get_dead_letter_producer, verify_topics_exist
)
from src.schemas.telemetry import SCHEMA_VERSION, ActionType

logger = logging.getLogger("jev_interceptor")

ARROW_BATCH_SIZE: Final[int] = 64
UDF_CONCURRENCY: Final[int] = 16

# Explicit schema
TELEMETRY_SCHEMA: Final[StructType] = StructType([
    StructField("schema_version", StringType()),
    StructField("event_id", StringType()),
    StructField("event_timestamp", StringType()),
    StructField("trace_id", StringType()),
    StructField("source", StringType()),
    StructField("agent", StructType([
        StructField("agent_id", StringType()),
        StructField("agent_name", StringType()),
        StructField("session_id", StringType()),
        StructField("tenant_id", StringType()),
        StructField("llm_provider", StringType()),
        StructField("llm_model", StringType()),
    ])),
    StructField("action_type", StringType()),
    StructField("payload", StructType([
        StructField("raw_command", StringType()),
        StructField("target_resource", StringType()),
        StructField("requested_privilege", StringType()),
        StructField("parameters", MapType(StringType(), StringType())),
    ])),
])

VERDICT_SCHEMA: Final[StructType] = StructType([
    StructField("verdict", StringType()),
    StructField("label", StringType()),
    StructField("confidence", DoubleType()),
    StructField("unsafe_mass", DoubleType()),
    StructField("reason", StringType()),
    StructField("latency_ms", DoubleType()),
    StructField("cost_usd", DoubleType()),
    StructField("degraded", BooleanType()),
    StructField("probabilities", MapType(StringType(), DoubleType())),
])

TRIPWIRES: Final[list[tuple[str, str]]] = [
    (r"(?is)\bdrop\s+(table|database|schema)\b", "DDL drop"),
    (r"(?is)\btruncate\s+table\b", "table truncation"),
    (r"(?is)\bdelete\s+from\b(?!.*\bwhere\b)", "unbounded DELETE"),
    (r"(?is)\bupdate\b.*\bset\b(?!.*\bwhere\b)", "unbounded UPDATE"),
    (r"(?is)\bgrant\s+all\b|\balter\s+user\b", "privilege escalation"),
    (r"(?is)rm\s+-rf\s+/", "recursive filesystem delete"),
]

_VALID_ACTION_TYPES: Final[list[str]] = [a.value for a in ActionType]


def _attempt_expr() -> Column:
    """How many times this event has already failed (0 for a fresh message).

    Spark 4 runs with ANSI mode on by default, so element_at() on an empty
    array and CAST('x' AS INT) THROW instead of returning NULL. The try_
    variants restore NULL-on-failure, which is what a header lookup needs.
    """
    return F.coalesce(
        F.expr(
            "try_cast(cast(try_element_at(filter(headers, h -> h.key = "
            f"'{ATTEMPT_HEADER}'), 1).value as string) as int)"
        ),
        F.lit(0),
    )


def _parse_error_expr() -> Column:
    """First failed contract check as a short label, else NULL.

    Mirrors the required parts of the Pydantic contract, checked in order so
    each record is labelled with its most fundamental failure.
    """
    command = F.col("e.payload.raw_command")
    checks: list[tuple[Column, str]] = [
        (F.col("kafka_value").isNull(), "empty_message"),
        (F.get_json_object(F.col("kafka_value").cast("string"), "$").isNull(), "invalid_json"),
        (F.col("e.schema_version").isNull() | (F.col("e.schema_version") != SCHEMA_VERSION),
         "unsupported_schema_version"),
        (F.col("e.event_id").isNull(), "missing_event_id"),
        (F.col("e.agent.session_id").isNull(), "missing_session_id"),
        (F.col("e.action_type").isNull() | ~F.col("e.action_type").isin(_VALID_ACTION_TYPES),
         "invalid_action_type"),
        (command.isNull() | (F.length(F.trim(command)) == 0), "missing_raw_command"),
    ]
    expr = F.lit(None).cast(StringType())
    for condition, label in reversed(checks):
        expr = F.when(condition, F.lit(label)).otherwise(expr)
    return expr


_EXECUTOR: ThreadPoolExecutor | None = None
_EXECUTOR_LOCK = threading.Lock()
_WORKER_STATE: dict[str, object] = {}

def _executor() -> ThreadPoolExecutor:
    """One long-lived pool per Python worker process.
    Lazily evaluated to prevent PySpark pickling errors on the driver.
    """
    import threading

    if "lock" not in _WORKER_STATE:
        _WORKER_STATE["lock"] = threading.Lock()
        
    with _WORKER_STATE["lock"]:  # type: ignore
        if "pool" not in _WORKER_STATE:
            _WORKER_STATE["pool"] = ThreadPoolExecutor(
                max_workers=UDF_CONCURRENCY, thread_name_prefix="jev"
            )
    return _WORKER_STATE["pool"]  # type: ignore


def _kafka_package() -> str:
    """Resolve the Kafka connector coordinate for THIS Spark build.

    The single most common Structured Streaming failure is a Scala version
    mismatch between the connector JAR and the runtime. Derive it rather than
    hardcoding: PySpark 3.x ships Scala 2.12, PySpark 4.x ships Scala 2.13.
    """
    spark_version = pyspark.__version__
    scala_version = "2.13" if int(spark_version.split(".")[0]) >= 4 else "2.12"
    return f"org.apache.spark:spark-sql-kafka-0-10_{scala_version}:{spark_version}"


def build_spark() -> SparkSession:
    os.environ.setdefault("PYSPARK_PYTHON", sys.executable)
    os.environ.setdefault("PYSPARK_DRIVER_PYTHON", sys.executable)

    return (
        SparkSession.builder.appName("JevGuardrailInterceptor")
        .master("local[*]")
        .config("spark.jars.packages", _kafka_package())
        .config("spark.jars.repositories", "https://repo1.maven.org/maven2")
        .config("spark.sql.execution.arrow.pyspark.enabled", "true")
        .config("spark.sql.execution.arrow.maxRecordsPerBatch", str(ARROW_BATCH_SIZE))
        .config("spark.sql.shuffle.partitions", "4")
        .config("spark.ui.showConsoleProgress", "false")
        .getOrCreate()
    )


def build_assess_udf(
    api_key: str, model: str, approve_at: float, block_at: float, timeout: float
):
    """Factory closing over config so executors don't need to read .env.

    NOTE: the key is captured into the serialised closure. Fine in local mode.
    On a real cluster, fetch it from a secrets manager inside the UDF instead.
    """

    @pandas_udf(StringType())
    def _assess(state_json: pd.Series, tripwire: pd.Series) -> pd.Series:
        """Arrow-batched. Receives ~64 rows, fires them concurrently."""

        def tripwire_label(value: object) -> str | None:
            if isinstance(value, str):
                cleaned = value.strip()
                return cleaned or None
            return None

        def score_one(index: int) -> str:
            hit = tripwire_label(tripwire.iloc[index])
            if hit is not None:
                # Deterministic block -- no API call, no spend.
                return RiskAssessment(
                    verdict=Verdict.BLOCK,
                    label="destructive",
                    confidence=1.0,
                    unsafe_mass=1.0,
                    reason=f"TRIPWIRE: {hit}",
                ).to_json()
            try:
                state = json.loads(state_json.iloc[index])
            except (TypeError, ValueError) as exc:
                return RiskAssessment(
                    verdict=Verdict.REVIEW,
                    label="unknown",
                    reason=f"FAIL_CLOSED: unreadable state: {exc}",
                    degraded=True,
                ).to_json()
            return assess_action(
                state=state, api_key=api_key, model=model,
                approve_at=approve_at, block_at=block_at, timeout=timeout,
            ).to_json()

        # Threads, not processes: these workers are blocked on sockets, so the
        # GIL is released and concurrency is real.
        # Threads, not processes: these workers are blocked on sockets, so the
        # GIL is released and concurrency is real. We use the global executor
        # so threads (and their connection pools) survive the micro-batch.
        results = list(_executor().map(score_one, range(len(state_json))))
        return pd.Series(results, index=state_json.index)

    return _assess


def read_telemetry(spark: SparkSession) -> DataFrame:
    """Kafka -> parsed, validated rows. Invalid rows are KEPT and labelled.

    The old `.filter(e.isNotNull())` was a silent drop. Every record now
    leaves this function with parse_error NULL (valid) or a reason -- plus
    its raw bytes and Kafka coordinates, so it can be dead-lettered exactly
    as it arrived.
    """
    settings = get_settings()
    jaas = (
        "org.apache.kafka.common.security.plain.PlainLoginModule required "
        f'username="{settings.kafka_api_key}" password="{settings.kafka_api_secret}";'
    )
    raw = (
        spark.readStream.format("kafka")
        .option("kafka.bootstrap.servers", settings.kafka_bootstrap_servers)
        .option("subscribe", settings.kafka_topic_agent_actions)
        .option("startingOffsets", "latest")
        .option("failOnDataLoss", "false")
        .option("maxOffsetsPerTrigger", str(settings.spark_max_offsets_per_trigger))
        .option("includeHeaders", "true")       # needed for the attempt counter
        .option("kafka.security.protocol", "SASL_SSL")
        .option("kafka.sasl.mechanism", "PLAIN")
        .option("kafka.sasl.jaas.config", jaas)
        .load()
    )
    parsed = raw.select(
        F.col("key").alias("kafka_key"),
        F.col("value").alias("kafka_value"),
        F.col("topic").alias("source_topic"),
        F.col("partition").alias("source_partition"),
        F.col("offset").alias("source_offset"),
        _attempt_expr().alias("dlq_attempt"),
        F.from_json(F.col("value").cast("string"), TELEMETRY_SCHEMA).alias("e"),
    )
    return parsed.withColumn("parse_error", _parse_error_expr()).select(
        "kafka_key", "kafka_value", "source_topic", "source_partition",
        "source_offset", "dlq_attempt", "parse_error", "e.*",
    )



def add_tripwire_column(df: DataFrame) -> DataFrame:
    """First matching tripwire label, else NULL. Evaluated in the JVM -- free."""
    command = F.col("payload.raw_command")
    expr = F.lit(None).cast(StringType())
    for pattern, label in reversed(TRIPWIRES):
        expr = F.when(command.rlike(pattern), F.lit(label)).otherwise(expr)
    return df.withColumn("tripwire", expr)


def intercept(df: DataFrame, assess: Callable[..., Column]) -> DataFrame:
    settings = get_settings()
    assess = build_assess_udf(
        api_key=settings.openrouter_api_key,
        model=settings.jev_model,
        approve_at=settings.jev_approve_at,
        block_at=settings.jev_block_at,
        timeout=settings.jev_timeout_seconds,
    )
    state = F.to_json(F.struct(
        F.struct(
            F.col("action_type").alias("action_type"),
            F.col("payload.raw_command").alias("raw_command"),
            F.col("payload.target_resource").alias("target"),
            F.col("payload.requested_privilege").alias("requested_privilege"),
        ).alias("action"),
        F.struct(
            F.col("agent.agent_name").alias("agent_name"),
            F.col("agent.tenant_id").alias("tenant_id"),
        ).alias("agent"),
    ))
    return (
        df.withColumn("state_json", state)
        .withColumn("assessment_json", assess(F.col("state_json"), F.col("tripwire")))
        .withColumn("a", F.from_json(F.col("assessment_json"), VERDICT_SCHEMA))
        .drop("state_json", "assessment_json")
    )


def console_view(df: DataFrame) -> DataFrame:
    """The human-readable projection. Display only -- the sink uses the full row."""
    return df.select(
        F.col("a.verdict").alias("verdict"),
        F.col("a.label").alias("label"),
        F.round(F.col("a.confidence"), 3).alias("conf"),
        F.col("agent.agent_name").alias("agent"),
        F.col("agent.session_id").alias("session"),
        F.col("action_type"),
        F.substring(F.col("payload.raw_command"), 1, 60).alias("command"),
        F.col("a.reason").alias("reason"),
        F.round(F.col("a.latency_ms"), 0).alias("ms"),
        F.col("a.degraded").alias("degraded"),
        F.col("source").alias("origin"),
    )

def _send_dead_letter(
    row: Row, stage: DLQStage, error_class: str, message: str, retryable: bool,
) -> None:
    key, value = row["kafka_key"], row["kafka_value"]
    get_dead_letter_producer().send(
        key=bytes(key) if key is not None else None,
        value=bytes(value) if value is not None else None,
        context=DeadLetterContext(
            stage=stage,
            error_class=error_class,
            error_message=message,
            retryable=retryable,
            attempt=int(row["dlq_attempt"] or 0) + 1,
            source_topic=row["source_topic"],
            source_partition=int(row["source_partition"]),
            source_offset=int(row["source_offset"]),
            event_id=row["event_id"],
        ),
    )


def make_batch_writer(assess: Callable[..., Column]) -> Callable[[DataFrame, int], None]:
    def write_batch(batch_df: DataFrame, batch_id: int) -> None:
        """Route one micro-batch: PARSE failures -> DLQ; the rest -> Jev -> ES.

        Two persists, for two different reasons:
          batch_df -- filtered twice (valid / invalid); without persist the
                      Kafka offset range is fetched twice.
          enriched -- acted on twice (show, collect); without persist the Jev
                      UDF runs twice and every event is billed twice.
        """
        dlq = get_dead_letter_producer()
        dead_lettered: Counter[str] = Counter()
        enriched: DataFrame | None = None
        batch_df.persist()
        try:
            # 1. PARSE -- contract violations never reach the paid API.
            invalid = batch_df.filter(F.col("parse_error").isNotNull()).select(
                "kafka_key", "kafka_value", "source_topic", "source_partition",
                "source_offset", "dlq_attempt", "parse_error", "event_id",
            ).collect()
            for row in invalid:
                _send_dead_letter(row, DLQStage.PARSE, row["parse_error"],
                                  f"failed validation: {row['parse_error']}", retryable=False)
                dead_lettered[DLQStage.PARSE.value] += 1

            # 2. Assess ONLY the valid rows.
            enriched = intercept(batch_df.filter(F.col("parse_error").isNull()), assess).persist()
            console_view(enriched).show(truncate=False, n=50)
            rows = enriched.collect()

            # 3. SINK -- per-document rejections become dead letters.
            succeeded, failures = index_documents(
                build_document(row.asDict(recursive=True), batch_id) for row in rows
            )
            by_event_id = {row["event_id"]: row for row in rows}
            sink_failed: set[str] = set()
            for failure in failures:
                row = by_event_id.get(failure.event_id)
                if row is None:
                    logger.error("Rejected document %s not found in batch", failure.event_id)
                    continue
                _send_dead_letter(row, DLQStage.SINK, failure.error_type,
                                  f"HTTP {failure.status}: {failure.reason}", failure.retryable)
                sink_failed.add(failure.event_id)
                dead_lettered[DLQStage.SINK.value] += 1

            # 4. ASSESS -- degraded verdicts are already indexed fail-closed as
            #    REVIEW; this letter is the work item to re-score them. Events
            #    that also failed SINK are skipped: that letter replays both.
            for row in rows:
                assessment = row["a"]
                if assessment and assessment["degraded"] and row["event_id"] not in sink_failed:
                    _send_dead_letter(row, DLQStage.ASSESS, "jev_degraded",
                                      assessment["reason"] or "", retryable=True)
                    dead_lettered[DLQStage.ASSESS.value] += 1

            # 5. Durable BEFORE return -- returning lets Spark commit offsets.
            dlq.flush_or_raise()

            verdicts = Counter(row["a"]["verdict"] for row in rows if row["a"])
            cost = sum((row["a"]["cost_usd"] or 0.0) for row in rows if row["a"])
            logger.info(
                "batch=%d valid=%d indexed=%d dead_lettered=%s verdicts=%s cost=$%.6f",
                batch_id, len(rows), succeeded, dict(dead_lettered), dict(verdicts), cost,
            )
        except Exception:
            # Spark fails the query; the checkpoint still holds this batch's
            # offsets, so a restart replays it. ES writes are idempotent by
            # _id, so replay is safe -- though Jev is billed again.
            logger.exception("batch=%d failed", batch_id)
            raise
        finally:
            if enriched is not None:
                enriched.unpersist()
            batch_df.unpersist()

    return write_batch



def main() -> None:
    settings = get_settings()
    logging.basicConfig(
        level=settings.log_level.upper(),
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%H:%M:%S",
    )

    for noisy in ("py4j", "elastic_transport"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    spark = build_spark()
    spark.sparkContext.setLogLevel("WARN")
    logger.info("Kafka connector: %s", _kafka_package())
    logger.info("Intercepting topic=%s", settings.kafka_topic_agent_actions)

    verify_topics_exist(settings.kafka_topic_agent_actions, settings.kafka_topic_dlq)

    ensure_index()

    probe = assess_action(
        state={"action": {"action_type": "SQL_QUERY", "raw_command": "SELECT 1"}},
        api_key=settings.openrouter_api_key,
        model=settings.jev_model,
        approve_at=settings.jev_approve_at,
        block_at=settings.jev_block_at,
        timeout=settings.jev_timeout_seconds,
    )
    if probe.degraded:
        logger.warning("Jev preflight degraded (%s) -- starting anyway", probe.reason)
    else:
        logger.info("Jev preflight OK: %s in %.0f ms", probe.label, probe.latency_ms)


    assess = build_assess_udf(
        api_key=settings.openrouter_api_key,
        model=settings.jev_model,
        approve_at=settings.jev_approve_at,
        block_at=settings.jev_block_at,
        timeout=settings.jev_timeout_seconds,
    )
    stream = add_tripwire_column(read_telemetry(spark))

    query = (
        stream.writeStream.foreachBatch(make_batch_writer(assess))
        .outputMode("append")
        .option("checkpointLocation", settings.spark_checkpoint_dir)
        .trigger(processingTime="5 seconds")
        .start()
    )
    try:
        query.awaitTermination()
    except KeyboardInterrupt:
        logger.warning("Stopping stream...")
        query.stop()
        spark.stop()


if __name__ == "__main__":
    main()
