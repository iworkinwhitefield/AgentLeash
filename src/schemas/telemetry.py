"""Canonical telemetry contract for agent actions flowing through the Guardrail Engine.

This schema is the shared language between the producers (Terminals 1 and 3),
the PySpark interceptor (Terminal 2), and the Elasticsearch index.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

SCHEMA_VERSION: Literal["1.0.0"] = "1.0.0"


class ActionType(str, Enum):
    """The class of side effect an agent is attempting."""

    SQL_QUERY = "SQL_QUERY"
    TOOL_CALL = "TOOL_CALL"
    API_REQUEST = "API_REQUEST"
    FILE_OPERATION = "FILE_OPERATION"
    SHELL_COMMAND = "SHELL_COMMAND"


class PrivilegeLevel(str, Enum):
    """Privilege the agent claims it needs. Claimed, not verified."""

    READ = "READ"
    WRITE = "WRITE"
    ADMIN = "ADMIN"


class EventSource(str, Enum):
    """Which harness emitted the event.

    EVALUATION USE ONLY. The interceptor in Terminal 2 must NEVER branch on this
    field — doing so would make the guardrail trivially correct in the demo and
    useless in production. It exists solely so we can score precision/recall
    after the fact.
    """

    SAFE_SIMULATOR = "SAFE_SIMULATOR"
    RED_TEAM = "RED_TEAM"
    PRODUCTION = "PRODUCTION"


class AgentIdentity(BaseModel):
    """Who is acting. session_id is the Kafka partition key."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    agent_id: str = Field(min_length=1, max_length=64)
    agent_name: str = Field(min_length=1, max_length=128)
    session_id: str = Field(min_length=1, max_length=64)
    tenant_id: str = Field(default="internal", max_length=64)
    llm_provider: str | None = Field(default=None, max_length=64)
    llm_model: str | None = Field(default=None, max_length=128)


class ActionPayload(BaseModel):
    """What the agent is attempting to execute."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    raw_command: str = Field(min_length=1, max_length=8192)
    target_resource: str | None = Field(default=None, max_length=512)
    requested_privilege: PrivilegeLevel = PrivilegeLevel.READ
    parameters: dict[str, Any] = Field(default_factory=dict)

    @field_validator("raw_command")
    @classmethod
    def _reject_blank_command(cls, value: str) -> str:
        """Trim surrounding whitespace but preserve the payload byte-for-byte otherwise.

        We deliberately do NOT sanitise, escape, or normalise the command. The
        interceptor must see exactly what the agent intended to run.
        """
        stripped = value.strip()
        if not stripped:
            raise ValueError("raw_command cannot be blank or whitespace-only")
        return stripped


class AgentTelemetryEvent(BaseModel):
    """One intercepted agent action. The unit of work for the entire pipeline."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0.0"] = SCHEMA_VERSION
    event_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    event_timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    trace_id: str = Field(min_length=1, max_length=64)
    source: EventSource
    agent: AgentIdentity
    action_type: ActionType
    payload: ActionPayload

    @field_validator("event_timestamp")
    @classmethod
    def _require_utc(cls, value: datetime) -> datetime:
        """Reject naive datetimes; normalise everything to UTC.

        Timezone-naive timestamps are the number one cause of broken windowed
        aggregations in streaming systems. Fail at the producer, not in Spark.
        """
        if value.tzinfo is None:
            raise ValueError("event_timestamp must be timezone-aware")
        return value.astimezone(timezone.utc)

    @property
    def partition_key(self) -> str:
        """All actions in one agent session must land on one partition, in order.

        This is what lets the Terminal 2 circuit breaker hold per-session state
        ("this session has tripped 3 rules -> kill it") without an external
        state store.
        """
        return self.agent.session_id

    def to_kafka_value(self) -> bytes:
        """Serialise to UTF-8 JSON for the wire."""
        return self.model_dump_json().encode("utf-8")

    def to_kafka_key(self) -> bytes:
        return self.partition_key.encode("utf-8")