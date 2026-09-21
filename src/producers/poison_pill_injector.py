"""Publish deliberately broken messages to exercise every dead-letter path.

These bypass the Pydantic contract on purpose: they model a buggy or
out-of-date upstream producer -- the situation a DLQ exists for.

    python -m src.producers.poison_pill_injector --dry-run
    python -m src.producers.poison_pill_injector
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from typing import Any

from confluent_kafka import KafkaError, Message, Producer

from src.config import get_settings
from src.schemas.telemetry import (
    ActionPayload, ActionType, AgentIdentity, AgentTelemetryEvent, EventSource,
)

logger = logging.getLogger("poison_pill_injector")


def _valid_event() -> dict[str, Any]:
    """A fully valid event (fresh event_id each call) as a plain dict."""
    return AgentTelemetryEvent(
        trace_id="poison-pill",
        source=EventSource.RED_TEAM,
        agent=AgentIdentity(agent_id="agent-ops-03", agent_name="InfraHealthAgent",
                            session_id="poison-session"),
        action_type=ActionType.SQL_QUERY,
        payload=ActionPayload(raw_command="SELECT 1", target_resource="warehouse.health"),
    ).model_dump(mode="json")


def _encode(event: dict[str, Any]) -> bytes:
    return json.dumps(event).encode("utf-8")


def build_cases() -> list[tuple[str, str, bytes]]:
    """(case, expected stage / class, raw bytes)."""
    future = _valid_event()
    future["schema_version"] = "2.0.0"
    unknown = _valid_event()
    unknown["action_type"] = "SELF_DESTRUCT"
    no_command = _valid_event()
    del no_command["payload"]["raw_command"]
    bad_time = _valid_event()
    bad_time["event_timestamp"] = "not-a-timestamp"

    return [
        ("truncated_json", "PARSE / invalid_json", b'{"event_id": "abc", "agent": {'),
        ("binary_garbage", "PARSE / invalid_json", b"\x00\xff\xfe\x10 definitely not json"),
        ("future_schema", "PARSE / unsupported_schema_version", _encode(future)),
        ("unknown_action", "PARSE / invalid_action_type", _encode(unknown)),
        ("missing_command", "PARSE / missing_raw_command", _encode(no_command)),
        # Passes OUR validator, costs one Jev call, then Elasticsearch's date
        # mapping rejects it. The DLQ is how you learn the two disagree.
        ("bad_timestamp", "SINK / 400 date parsing error", _encode(bad_time)),
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description="Poison pill injector")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    settings = get_settings()
    logging.basicConfig(level=settings.log_level.upper(),
                        format="%(asctime)s | %(levelname)-8s | %(message)s", datefmt="%H:%M:%S")
    cases = build_cases()
    for name, expected, _ in cases:
        logger.info("%-16s -> expect %s", name, expected)
    if args.dry_run:
        sys.exit(0)

    failures: list[str] = []

    def on_delivery(err: KafkaError | None, _msg: Message) -> None:
        if err is not None:
            failures.append(err.str())

    producer = Producer(settings.kafka_client_config(client_id="poison-pill-injector"))
    for _, _, payload in cases:
        producer.produce(settings.kafka_topic_agent_actions, key=b"poison-session",
                         value=payload, on_delivery=on_delivery)
    remaining = producer.flush(15.0)
    if remaining or failures:
        logger.error("%d undelivered, %d failed", remaining, len(failures))
        sys.exit(1)
    logger.info("Sent %d poison pills", len(cases))


if __name__ == "__main__":
    main()