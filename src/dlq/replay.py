"""Inspect and replay the dead-letter queue.

A DLQ that nobody can read is a slower way of losing data. This tool
summarises what is parked there and re-publishes eligible records -- the
ORIGINAL bytes, never a re-serialised copy -- onto the main topic.

    python -m src.dlq.replay --inspect
    python -m src.dlq.replay --stage ASSESS
    python -m src.dlq.replay --stage SINK --include-non-retryable --dry-run
"""

from __future__ import annotations

import argparse
import logging
import sys
import uuid
from collections import Counter
from collections.abc import Iterator

from confluent_kafka import Consumer, KafkaError, KafkaException, Message, Producer
from pydantic import ValidationError

from src.config import get_settings
from src.dlq.dead_letter import ATTEMPT_HEADER, DeadLetterContext, DLQStage

logger = logging.getLogger("dlq_replay")


def drain(consumer: Consumer, idle_seconds: float) -> Iterator[Message]:
    """Yield messages until the topic has been quiet for `idle_seconds`.

    A replay is a bounded job, not a daemon: it stops once it has caught up.
    """
    idle = 0.0
    while idle < idle_seconds:
        msg = consumer.poll(1.0)
        if msg is None:
            idle += 1.0
            continue
        idle = 0.0
        error = msg.error()
        if error is not None:
            if error.code() == KafkaError._PARTITION_EOF:
                continue
            raise KafkaException(error)
        yield msg


def run_inspect(idle_seconds: float) -> int:
    settings = get_settings()
    # Throwaway group that never commits: inspecting must not move any cursor.
    consumer = Consumer(settings.kafka_consumer_config(
        "guardrail-dlq-inspect", f"guardrail-dlq-inspect-{uuid.uuid4().hex[:8]}"))
    consumer.subscribe([settings.kafka_topic_dlq])

    summary: Counter[tuple[str, str, bool, bool]] = Counter()
    samples: dict[tuple[str, str, bool, bool], str] = {}
    unreadable = 0
    try:
        for msg in drain(consumer, idle_seconds):
            try:
                ctx = DeadLetterContext.from_headers(msg.headers())
            except ValidationError:
                unreadable += 1
                continue
            key = (ctx.stage.value, ctx.error_class, ctx.retryable,
                   ctx.attempt >= settings.dlq_max_attempts)
            summary[key] += 1
            samples.setdefault(key, ctx.error_message)
    finally:
        consumer.close()

    print(f"\n{'stage':<8}{'error_class':<34}{'retryable':>10}{'exhausted':>10}{'count':>7}")
    for key, count in sorted(summary.items()):
        stage, error_class, retryable, exhausted = key
        print(f"{stage:<8}{error_class[:33]:<34}{str(retryable):>10}{str(exhausted):>10}{count:>7}")
        print(f"        e.g. {samples[key][:90]}")
    print(f"\ntotal={sum(summary.values())} unreadable={unreadable}")
    return 0


def run_replay(
    stages: set[DLQStage], include_non_retryable: bool, dry_run: bool, idle_seconds: float,
) -> int:
    settings = get_settings()
    # One consumer group per replay POLICY. A committed offset means "every
    # record before this was handled". Skipping a non-retryable record is not
    # handling it -- so a later run with a different policy needs its own
    # cursor, or it would never see what this run skipped.
    policy = "-".join(sorted(s.value for s in stages)).lower()
    group = f"guardrail-dlq-replay.{policy}.{'all' if include_non_retryable else 'retryable'}"
    consumer = Consumer(settings.kafka_consumer_config("guardrail-dlq-replay", group))
    producer = None if dry_run else Producer(
        settings.kafka_client_config(client_id="guardrail-dlq-replay"))
    delivery_failures: list[str] = []

    def on_delivery(err: KafkaError | None, _msg: Message) -> None:
        if err is not None:
            delivery_failures.append(err.str())

    counts: Counter[str] = Counter()
    consumer.subscribe([settings.kafka_topic_dlq])
    try:
        for msg in drain(consumer, idle_seconds):
            try:
                ctx = DeadLetterContext.from_headers(msg.headers())
            except ValidationError:
                counts["unreadable"] += 1
                continue

            if ctx.stage not in stages:
                counts["other_stage"] += 1
            elif not ctx.retryable and not include_non_retryable:
                counts["not_retryable"] += 1
            elif ctx.attempt >= settings.dlq_max_attempts:
                counts["exhausted"] += 1           # needs a human, not a retry
            elif producer is None:
                counts["would_replay"] += 1
            else:
                while True:
                    try:
                        producer.produce(
                            settings.kafka_topic_agent_actions,
                            key=msg.key(),
                            value=msg.value(),
                            # Failure count rides along; the interceptor adds
                            # one if this attempt fails too.
                            headers=[(ATTEMPT_HEADER, str(ctx.attempt).encode("utf-8"))],
                            on_delivery=on_delivery,
                        )
                        break
                    except BufferError:
                        producer.poll(0.5)
                producer.poll(0)
                counts["replayed"] += 1

        if producer is not None:
            remaining = producer.flush(30.0)
            if remaining or delivery_failures:
                logger.error("Replay NOT committed: %d undelivered, %d failed. Re-running is safe.",
                             remaining, len(delivery_failures))
                return 1
            try:
                consumer.commit(asynchronous=False)
            except KafkaException as exc:
                if exc.args[0].code() != KafkaError._NO_OFFSET:   # nothing consumed
                    raise
    finally:
        consumer.close()

    logger.info("group=%s %s", group, dict(counts))
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Inspect or replay the guardrail DLQ")
    parser.add_argument("--inspect", action="store_true", help="Summarise; replay nothing")
    parser.add_argument("--stage", nargs="+", choices=[s.value for s in DLQStage],
                        default=[DLQStage.ASSESS.value, DLQStage.SINK.value])
    parser.add_argument("--include-non-retryable", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--idle-seconds", type=float, default=10.0)
    args = parser.parse_args()

    logging.basicConfig(level=get_settings().log_level.upper(),
                        format="%(asctime)s | %(levelname)-8s | %(message)s", datefmt="%H:%M:%S")
    if args.inspect:
        sys.exit(run_inspect(args.idle_seconds))
    sys.exit(run_replay({DLQStage(s) for s in args.stage},
                        args.include_non_retryable, args.dry_run, args.idle_seconds))


if __name__ == "__main__":
    main()