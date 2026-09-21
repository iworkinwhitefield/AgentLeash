"""Dead-letter queue contract and producer.

Wire format -- the same shape Kafka Connect uses for its own DLQ:
    key     = the ORIGINAL message key, untouched
    value   = the ORIGINAL message bytes, untouched
    headers = error context under the "__dlq." prefix

The value is never re-serialised. If the bug is in our parser, pushing the
record back through that parser would launder away the evidence.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from enum import Enum
from functools import lru_cache
from typing import Any, Final

from confluent_kafka import KafkaError, Message, Producer
from confluent_kafka.admin import AdminClient
from pydantic import BaseModel, ConfigDict, Field, field_validator

from src.config import get_settings

logger = logging.getLogger(__name__)

HEADER_PREFIX: Final[str] = "__dlq."
ATTEMPT_HEADER: Final[str] = f"{HEADER_PREFIX}attempt"
_MAX_TEXT: Final[int] = 1000


class DLQStage(str, Enum):
    PARSE = "PARSE"    # never reached the model: malformed or contract-violating
    ASSESS = "ASSESS"  # Jev unavailable; indexed fail-closed as REVIEW, needs re-scoring
    SINK = "SINK"      # scored, but Elasticsearch rejected the document


class DeadLetterContext(BaseModel):
    """Why a record was dead-lettered and exactly where it came from."""

    # extra="ignore" on purpose: this model READS headers, possibly written by
    # a newer version of this code. Unknown keys must not make a letter unreadable.
    model_config = ConfigDict(frozen=True, extra="ignore")

    stage: DLQStage
    error_class: str
    error_message: str
    retryable: bool
    attempt: int = Field(ge=1)
    source_topic: str
    source_partition: int
    source_offset: int
    event_id: str | None = None
    failed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("error_class", "error_message", mode="before")
    @classmethod
    def _truncate(cls, value: Any) -> str:
        # Truncate, never reject. A DLQ that can refuse a dead letter because
        # its error text was too long is a DLQ that loses data.
        return str(value)[:_MAX_TEXT] if value is not None else ""

    def to_headers(self) -> list[tuple[str, bytes]]:
        headers: list[tuple[str, bytes]] = []
        for name, value in self.model_dump(mode="json").items():
            if value is None:
                continue
            text = value if isinstance(value, str) else json.dumps(value)
            headers.append((f"{HEADER_PREFIX}{name}", text.encode("utf-8")))
        return headers

    @classmethod
    def from_headers(cls, headers: list[tuple[str, bytes | None]] | None) -> "DeadLetterContext":
        fields: dict[str, str] = {}
        for name, value in headers or []:
            if name.startswith(HEADER_PREFIX) and value is not None:
                fields[name[len(HEADER_PREFIX):]] = value.decode("utf-8", errors="replace")
        return cls.model_validate(fields)


class DeadLetterDeliveryError(RuntimeError):
    """Dead letters could not be durably written. The batch must not commit."""


def verify_topics_exist(*topics: str, timeout: float = 15.0) -> None:
    """Fail fast at startup if a required topic is missing or not visible.

    Without this, a missing DLQ topic only surfaces mid-stream as an opaque
    'N undelivered, 0 rejected': librdkafka waits up to
    topic.metadata.propagation.max.ms (30s by default) before declaring a
    topic unknown -- longer than the DLQ flush timeout -- so the real error
    never reaches the delivery callback in time.
    """
    admin = AdminClient(get_settings().kafka_client_config(client_id="guardrail-preflight"))
    metadata = admin.list_topics(timeout=timeout)
    problems: list[str] = []
    for topic in topics:
        info = metadata.topics.get(topic)
        if info is None:
            problems.append(f"'{topic}' not found (missing, or not visible to this API key)")
        elif info.error is not None:
            problems.append(f"'{topic}': {info.error.str()}")
    if problems:
        raise RuntimeError("Kafka preflight failed: " + "; ".join(problems))
    logger.info("Kafka preflight OK: %s", ", ".join(topics))


class DeadLetterProducer:
    """Buffers one micro-batch's dead letters and flushes them durably."""

    def __init__(self) -> None:
        settings = get_settings()
        self._producer = Producer(settings.kafka_client_config(client_id="guardrail-dlq"))
        self._topic = settings.kafka_topic_dlq
        self._flush_timeout = settings.dlq_flush_timeout_seconds
        self._failures: list[str] = []
        self._pending = 0

    def _on_delivery(self, err: KafkaError | None, _msg: Message) -> None:
        # Delivery callbacks run inside poll()/flush() on the calling thread,
        # so this list needs no lock.
        if err is not None:
            self._failures.append(err.str())

    def send(self, key: bytes | None, value: bytes | None, context: DeadLetterContext) -> None:
        while True:
            try:
                self._producer.produce(
                    self._topic, key=key, value=value,
                    headers=context.to_headers(), on_delivery=self._on_delivery,
                )
                break
            except BufferError:
                self._producer.poll(0.5)   # serve delivery reports to free space
        self._pending += 1
        self._producer.poll(0)

    def flush_or_raise(self) -> int:
        """Block until every dead letter is acknowledged by the broker.

        Must be called before the foreachBatch function returns: returning is
        what lets Spark commit the batch's offsets.
        """
        sent, self._pending = self._pending, 0
        remaining = self._producer.flush(self._flush_timeout)
        failures, self._failures = self._failures, []
        
        if remaining or failures:
            hint = (
                " -- no delivery report within the timeout usually means the broker is "
                "unreachable, the topic is missing, or the key lacks WRITE access"
                if remaining and not failures else ""
            )
            raise DeadLetterDeliveryError(
                f"{remaining} dead letter(s) undelivered, {len(failures)} rejected: "
                f"{failures[:3]}{hint}"
            )
        return sent


@lru_cache(maxsize=1)
def get_dead_letter_producer() -> DeadLetterProducer:
    return DeadLetterProducer()