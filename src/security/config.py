from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Optional
import json
import os


def _parse_bool_env(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _normalize_prefix(prefix: str, fallback: str) -> str:
    clean = (prefix or fallback).strip().strip("/")
    return clean or fallback


def _parse_secret_map(raw: Optional[str]) -> Dict[str, str]:
    if not raw:
        return {}

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return {}

    if not isinstance(payload, dict):
        return {}

    mapped: Dict[str, str] = {}
    for env_name, secret_name in payload.items():
        if not isinstance(env_name, str) or not isinstance(secret_name, str):
            continue

        env_key = env_name.strip()
        secret_key = secret_name.strip()
        if env_key and secret_key:
            mapped[env_key] = secret_key

    return mapped


@dataclass(frozen=True)
class SecuritySettings:
    app_env: str
    azure_key_vault_url: Optional[str]
    require_key_vault: bool
    key_vault_secret_env_map: Dict[str, str] = field(default_factory=dict)

    azure_storage_account_url: Optional[str] = None
    azure_storage_connection_string: Optional[str] = None
    azure_storage_container: str = "cyberguard-data"
    storage_connection_string_secret_name: Optional[str] = None

    blob_prediction_logging_enabled: bool = True
    blob_logs_prefix: str = "logs"
    blob_raw_prefix: str = "raw"
    blob_processed_prefix: str = "processed"

    local_prediction_log_path: str = "logs/phishing_attempts.log"

    @classmethod
    def from_env(cls) -> "SecuritySettings":
        app_env = os.getenv("APP_ENV", "dev").strip().lower() or "dev"

        vault_url = os.getenv("AZURE_KEY_VAULT_URL", "").strip() or None
        storage_account_url = os.getenv("AZURE_STORAGE_ACCOUNT_URL", "").strip() or None
        storage_connection_string = os.getenv("AZURE_STORAGE_CONNECTION_STRING", "").strip() or None

        key_vault_secret_env_map = _parse_secret_map(os.getenv("KEYVAULT_SECRET_ENV_MAP"))

        return cls(
            app_env=app_env,
            azure_key_vault_url=vault_url,
            require_key_vault=_parse_bool_env("KEYVAULT_REQUIRED", False),
            key_vault_secret_env_map=key_vault_secret_env_map,
            azure_storage_account_url=storage_account_url,
            azure_storage_connection_string=storage_connection_string,
            azure_storage_container=(os.getenv("AZURE_STORAGE_CONTAINER", "cyberguard-data").strip() or "cyberguard-data"),
            storage_connection_string_secret_name=(
                os.getenv("KV_SECRET_STORAGE_CONNECTION_STRING", "").strip() or None
            ),
            blob_prediction_logging_enabled=_parse_bool_env("BLOB_PREDICTION_LOGGING_ENABLED", True),
            blob_logs_prefix=_normalize_prefix(os.getenv("BLOB_LOGS_PREFIX", "logs"), "logs"),
            blob_raw_prefix=_normalize_prefix(os.getenv("BLOB_RAW_PREFIX", "raw"), "raw"),
            blob_processed_prefix=_normalize_prefix(os.getenv("BLOB_PROCESSED_PREFIX", "processed"), "processed"),
            local_prediction_log_path=(
                os.getenv("LOCAL_PREDICTION_LOG_PATH", "logs/phishing_attempts.log").strip()
                or "logs/phishing_attempts.log"
            ),
        )

    @staticmethod
    def _compose_blob_path(prefix: str, relative_path: str) -> str:
        clean_relative = relative_path.strip().lstrip("/")
        if not clean_relative:
            return prefix
        return f"{prefix}/{clean_relative}"

    def raw_blob_path(self, relative_path: str) -> str:
        return self._compose_blob_path(self.blob_raw_prefix, relative_path)

    def processed_blob_path(self, relative_path: str) -> str:
        return self._compose_blob_path(self.blob_processed_prefix, relative_path)

    def prediction_blob_path(self, at: Optional[datetime] = None) -> str:
        timestamp = at or datetime.now(timezone.utc)
        date_prefix = timestamp.strftime("predictions/%Y/%m/%d")
        filename = "predictions.jsonl"
        return self._compose_blob_path(self.blob_logs_prefix, f"{date_prefix}/{filename}")
