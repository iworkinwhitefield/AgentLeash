"""Centralised, validated runtime configuration for AgentLeash.

AGENTLEASH_ENV_FILE selects which file is loaded:
    .env          (default) managed cloud: Confluent, Elastic Cloud, OpenRouter
    .env.compose            local docker-compose stack with the mock Jev service
"""

from __future__ import annotations

import logging
import os
from functools import lru_cache
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)

ENV_FILE: str = os.environ.get("AGENTLEASH_ENV_FILE", ".env")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=ENV_FILE, env_file_encoding="utf-8", extra="ignore", case_sensitive=False,
    )

    # --- Kafka -----------------------------------------------------------------
    kafka_bootstrap_servers: str = Field(min_length=1)
    kafka_security_protocol: Literal["SASL_SSL", "PLAINTEXT"] = "SASL_SSL"
    kafka_api_key: str = Field(default="", repr=False)
    kafka_api_secret: str = Field(default="", repr=False)
    kafka_topic_agent_actions: str = "agent.actions.raw"
    kafka_topic_dlq: str = "agent.actions.dlq"

    # --- Jev (OpenRouter Decisions API, or the local mock) -----------------------
    openrouter_api_key: str = Field(min_length=1, repr=False)
    jev_endpoint: str = "https://openrouter.ai/api/alpha/decisions"
    jev_model: str = "typesafe/jev-1.13"
    jev_approve_at: float = Field(default=0.90, ge=0.0, le=1.0)
    jev_block_at: float = Field(default=0.90, ge=0.0, le=1.0)
    jev_timeout_seconds: float = Field(default=8.0, gt=0.0)

    # --- Elasticsearch ----------------------------------------------------------
    elastic_hosts: str | None = None
    elastic_username: str | None = None
    elastic_password: str | None = Field(default=None, repr=False)
    elastic_cloud_id: str | None = None
    elastic_api_key: str | None = Field(default=None, repr=False)
    elastic_verify_certs: bool = True
    elastic_index_verdicts: str = "agent-guardrail-verdicts"
    elastic_bulk_timeout: int = 30

    # --- Spark ----------------------------------------------------------------------
    spark_checkpoint_dir: str = "./.checkpoints/jev_interceptor"
    spark_max_offsets_per_trigger: int = Field(default=200, gt=0)
    spark_starting_offsets: Literal["earliest", "latest"] = "latest"

    # --- Dead-letter queue ------------------------------------------------------------
    dlq_max_attempts: int = Field(default=3, ge=1)
    dlq_flush_timeout_seconds: float = Field(default=15.0, gt=0)

    log_level: str = "INFO"

    # --- Validation -------------------------------------------------------------------
    @model_validator(mode="after")
    def _kafka_credentials_match_protocol(self) -> "Settings":
        if self.kafka_security_protocol == "SASL_SSL" and not (self.kafka_api_key and self.kafka_api_secret):
            raise ValueError("KAFKA_API_KEY and KAFKA_API_SECRET are required with SASL_SSL")
        return self

    @model_validator(mode="after")
    def _require_one_elastic_target(self) -> "Settings":
        if not self.elastic_cloud_id and not self.elastic_hosts:
            raise ValueError("Set either ELASTIC_CLOUD_ID or ELASTIC_HOSTS")
        return self

    @model_validator(mode="after")
    def _verdict_bands_must_not_overlap(self) -> "Settings":
        if self.jev_approve_at + self.jev_block_at <= 1.0:
            raise ValueError(
                f"JEV_APPROVE_AT ({self.jev_approve_at}) + JEV_BLOCK_AT "
                f"({self.jev_block_at}) must exceed 1.0 or the verdict bands overlap"
            )
        return self

    # --- Kafka client configs ------------------------------------------------------
    def _kafka_connection(self, client_id: str) -> dict[str, object]:
        """Bootstrap + security: the ONLY place transport differs by environment."""
        config: dict[str, object] = {
            "bootstrap.servers": self.kafka_bootstrap_servers,
            "security.protocol": self.kafka_security_protocol,
            "client.id": client_id,
        }
        if self.kafka_security_protocol == "SASL_SSL":
            config.update({
                "sasl.mechanisms": "PLAIN",
                "sasl.username": self.kafka_api_key,
                "sasl.password": self.kafka_api_secret,
            })
        return config

    def kafka_client_config(self, client_id: str) -> dict[str, object]:
        """Producer config. Also valid for AdminClient, which is a producer handle."""
        return {
            **self._kafka_connection(client_id),
            "acks": "all",
            "enable.idempotence": True,
            "retries": 5,
            "linger.ms": 50,
            "compression.type": "lz4",
        }

    def kafka_consumer_config(self, client_id: str, group_id: str) -> dict[str, object]:
        """Consumer config. Auto-commit off: callers commit after work is durable."""
        return {
            **self._kafka_connection(client_id),
            "group.id": group_id,
            "auto.offset.reset": "earliest",
            "enable.auto.commit": False,
        }

    def spark_kafka_options(self) -> dict[str, str]:
        """The same transport settings in the Spark Kafka source's option format."""
        options = {
            "kafka.bootstrap.servers": self.kafka_bootstrap_servers,
            "kafka.security.protocol": self.kafka_security_protocol,
        }
        if self.kafka_security_protocol == "SASL_SSL":
            options["kafka.sasl.mechanism"] = "PLAIN"
            options["kafka.sasl.jaas.config"] = (
                "org.apache.kafka.common.security.plain.PlainLoginModule required "
                f'username="{self.kafka_api_key}" password="{self.kafka_api_secret}";'
            )
        return options


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cached Settings; raises ValidationError if the env file is incomplete."""
    return Settings()  # type: ignore[call-arg]