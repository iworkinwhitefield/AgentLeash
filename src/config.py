from __future__ import annotations

import logging
from functools import lru_cache

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


class Settings(BaseSettings):

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    kafka_bootstrap_servers: str = Field(min_length=1)
    kafka_api_key: str = Field(min_length=1, repr=False)
    kafka_api_secret: str = Field(min_length=1, repr=False)
    kafka_topic_agent_actions: str = "agent.actions.raw"
    log_level: str = "INFO"
    openrouter_api_key: str = Field(min_length=1, repr=False)
    jev_model: str = "typesafe/jev-1.13"
    jev_approve_at: float = Field(default=0.90, ge=0.0, le=1.0)
    jev_block_at: float = Field(default=0.90, ge=0.0, le=1.0)
    jev_timeout_seconds: float = Field(default=8.0, gt=0.0)
    spark_checkpoint_dir: str = "./.checkpoints/jev_interceptor"
    spark_max_offsets_per_trigger: int = Field(default=200, gt=0)
    
    # Elastic Settings
    elastic_cloud_id: str | None = None
    elastic_hosts: str | None = None  # Added to prevent AttributeError in the validator
    elastic_api_key: str | None = Field(default=None, repr=False)
    elastic_verify_certs: bool = True
    elastic_index_verdicts: str = "agent-guardrail-verdicts"
    elastic_bulk_timeout: int = 30
    
    kafka_topic_dlq: str = "agent.actions.dlq"
    dlq_max_attempts: int = Field(default=3, ge=1)
    dlq_flush_timeout_seconds: float = Field(default=15.0, gt=0)

    def kafka_consumer_config(self, client_id: str, group_id: str) -> dict[str, object]:
        """Auth plus consumer settings.

        Separate from kafka_client_config because producer-only keys (acks,
        enable.idempotence, linger.ms) make librdkafka warn on every consumer
        start. Auto-commit is off: callers commit only after their work is
        durable.
        """
        return {
            "bootstrap.servers": self.kafka_bootstrap_servers,
            "security.protocol": "SASL_SSL",
            "sasl.mechanisms": "PLAIN",
            "sasl.username": self.kafka_api_key,
            "sasl.password": self.kafka_api_secret,
            "client.id": client_id,
            "group.id": group_id,
            "auto.offset.reset": "earliest",
            "enable.auto.commit": False,
        }

    @model_validator(mode="after")
    def _verdict_bands_must_not_overlap(self) -> "Settings":
        # ALLOW needs p(safe) >= approve_at; BLOCK needs p(unsafe) >= block_at.
        # With p(safe) + p(unsafe) = 1 the bands are disjoint iff the sum > 1.
        if self.jev_approve_at + self.jev_block_at <= 1.0:
            raise ValueError(
                f"JEV_APPROVE_AT ({self.jev_approve_at}) + JEV_BLOCK_AT "
                f"({self.jev_block_at}) must exceed 1.0 or the verdict bands overlap"
            )
        return self

    @model_validator(mode="after")
    def _require_one_elastic_target(self) -> "Settings":
        if not self.elastic_cloud_id and not self.elastic_hosts:
            raise ValueError("Set either ELASTIC_CLOUD_ID or ELASTIC_HOSTS in your .env")
        return self

    def kafka_client_config(self, client_id: str) -> dict[str, object]:
        return {
            "bootstrap.servers": self.kafka_bootstrap_servers,
            "security.protocol": "SASL_SSL",
            "sasl.mechanisms": "PLAIN",
            "sasl.username": self.kafka_api_key,
            "sasl.password": self.kafka_api_secret,
            "client.id": client_id,
            "acks": "all",
            "enable.idempotence": True,
            "retries": 5,
            "linger.ms": 50,
            "compression.type": "lz4",
        }


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    settings = Settings()  # type: ignore[call-arg]
    logger.debug("Configuration loaded for topic=%s", settings.kafka_topic_agent_actions)
    return settings