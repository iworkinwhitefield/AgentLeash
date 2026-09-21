"""Terminal 1 — Safe Agent Telemetry Generator.

Emits a steady stream of BENIGN agent actions to Kafka, simulating well-behaved
autonomous agents doing routine analytics work. This is the baseline traffic the
guardrail must NOT block; false positives here are what make a security system
get switched off in production.

Usage:
    python -m src.producers.safe_agent_simulator --eps 2 --max-events 100
    python -m src.producers.safe_agent_simulator --eps 5            # runs until Ctrl-C
"""

from __future__ import annotations

import argparse
import logging
import random
import signal
import sys
import time
import uuid
from types import FrameType

from confluent_kafka import KafkaError, KafkaException, Message, Producer

from src.config import get_settings
from src.schemas.telemetry import (
    ActionPayload,
    ActionType,
    AgentIdentity,
    AgentTelemetryEvent,
    EventSource,
    PrivilegeLevel,
)

logger = logging.getLogger("safe_agent_simulator")

_SHUTDOWN = False

# (action_type, raw_command, target_resource, privilege)
_SAFE_ACTIONS: list[tuple[ActionType, str, str, PrivilegeLevel]] = [
    (ActionType.SQL_QUERY,
     "SELECT order_id, total_amount FROM sales.orders WHERE order_date >= CURRENT_DATE - 7",
     "warehouse.sales.orders", PrivilegeLevel.READ),
    (ActionType.SQL_QUERY,
     "SELECT COUNT(*) AS active_users FROM analytics.dim_user WHERE is_active = TRUE",
     "warehouse.analytics.dim_user", PrivilegeLevel.READ),
    (ActionType.SQL_QUERY,
     "SELECT region, AVG(latency_ms) FROM metrics.api_latency GROUP BY region",
     "warehouse.metrics.api_latency", PrivilegeLevel.READ),
    (ActionType.TOOL_CALL,
     "vector_search(index='product_docs', query='refund policy', top_k=5)",
     "tool:vector_search", PrivilegeLevel.READ),
    (ActionType.TOOL_CALL,
     "summarise_document(doc_id='RPT-2291', max_tokens=400)",
     "tool:summarise_document", PrivilegeLevel.READ),
    (ActionType.API_REQUEST,
     "GET /v1/internal/inventory/status?warehouse=EU-WEST",
     "https://internal-api.corp/v1/inventory", PrivilegeLevel.READ),
    (ActionType.API_REQUEST,
     "GET /v1/reporting/dashboards/47/widgets",
     "https://internal-api.corp/v1/reporting", PrivilegeLevel.READ),
    (ActionType.FILE_OPERATION,
     "read_file(path='/mnt/reports/weekly_summary.csv')",
     "/mnt/reports/weekly_summary.csv", PrivilegeLevel.READ),
]

_AGENT_PROFILES: list[tuple[str, str]] = [
    ("agent-analytics-01", "RevenueInsightAgent"),
    ("agent-support-02", "CustomerSupportAgent"),
    ("agent-ops-03", "InfraHealthAgent"),
]


def _handle_signal(signum: int, _frame: FrameType | None) -> None:
    """Flip the shutdown flag so the main loop can drain the producer cleanly."""
    global _SHUTDOWN
    logger.warning("Received signal %s — draining producer buffer...", signum)
    _SHUTDOWN = True


def _delivery_report(err: KafkaError | None, msg: Message) -> None:
    """Async callback fired once the broker acks (or rejects) each message.

    Kafka producers are asynchronous. Without this callback a failed send is a
    silent data-loss event — the code looks like it worked.
    """
    if err is not None:
        logger.error("DELIVERY FAILED key=%s error=%s", msg.key(), err.str())
        return
    logger.info(
        "delivered topic=%s partition=%s offset=%s key=%s",
        msg.topic(), msg.partition(), msg.offset(),
        msg.key().decode("utf-8") if msg.key() else None,
    )


def build_safe_event(session_ids: dict[str, str]) -> AgentTelemetryEvent:
    """Construct one validated, benign telemetry event."""
    agent_id, agent_name = random.choice(_AGENT_PROFILES)
    action_type, command, target, privilege = random.choice(_SAFE_ACTIONS)

    return AgentTelemetryEvent(
        trace_id=uuid.uuid4().hex[:16],
        source=EventSource.SAFE_SIMULATOR,
        agent=AgentIdentity(
            agent_id=agent_id,
            agent_name=agent_name,
            session_id=session_ids[agent_id],
            tenant_id="internal",
            llm_provider="groq",
            llm_model="llama-3.3-70b-versatile",
        ),
        action_type=action_type,
        payload=ActionPayload(
            raw_command=command,
            target_resource=target,
            requested_privilege=privilege,
            parameters={"initiated_by": "scheduled_job"},
        ),
    )


def run(eps: float, max_events: int) -> int:
    """Produce events at `eps` per second. Returns a process exit code."""
    settings = get_settings()
    producer = Producer(settings.kafka_client_config(client_id="safe-agent-simulator"))
    topic = settings.kafka_topic_agent_actions

    # One stable session per agent for this process run, so the interceptor sees
    # a coherent per-session action history on a single partition.
    session_ids = {agent_id: uuid.uuid4().hex[:12] for agent_id, _ in _AGENT_PROFILES}
    interval = 1.0 / eps if eps > 0 else 0.0
    sent = 0

    logger.info("Producing to topic=%s at %.2f eps (sessions=%s)", topic, eps, session_ids)

    try:
        while not _SHUTDOWN and (max_events == 0 or sent < max_events):
            event = build_safe_event(session_ids)
            try:
                producer.produce(
                    topic=topic,
                    key=event.to_kafka_key(),
                    value=event.to_kafka_value(),
                    on_delivery=_delivery_report,
                )
            except BufferError:
                # Local queue is full: the broker is slower than we are.
                logger.warning("Local producer queue full — backing off 1s")
                producer.poll(1.0)
                continue
            except KafkaException:
                logger.exception("Unrecoverable produce error")
                return 1

            sent += 1
            producer.poll(0)   # serve delivery callbacks without blocking
            time.sleep(interval)

    except KeyboardInterrupt:
        logger.warning("Interrupted by user")
    finally:
        remaining = producer.flush(timeout=10.0)
        if remaining > 0:
            logger.error("%d message(s) NOT delivered before shutdown", remaining)
            return 1
        logger.info("Flushed cleanly. Total events produced: %d", sent)

    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Safe agent telemetry generator (Terminal 1)")
    parser.add_argument("--eps", type=float, default=2.0, help="Events per second (default: 2.0)")
    parser.add_argument("--max-events", type=int, default=0, help="Stop after N events; 0 = run forever")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    settings = get_settings()
    logging.basicConfig(
        level=settings.log_level.upper(),
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%H:%M:%S",
    )
    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)
    sys.exit(run(eps=args.eps, max_events=args.max_events))


if __name__ == "__main__":
    main()