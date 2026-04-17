from datetime import datetime, timezone
from typing import Any, Dict, Optional
import hashlib
import json
import logging
import mimetypes
import os

from src.security.config import SecuritySettings
from src.security.identity import create_azure_credential

try:
    from azure.core.exceptions import ResourceExistsError, ResourceNotFoundError
    from azure.storage.blob import BlobServiceClient, ContentSettings
except Exception:  # pragma: no cover - optional dependency
    BlobServiceClient = None
    ContentSettings = None
    ResourceExistsError = Exception
    ResourceNotFoundError = Exception


class BlobStorageManager:
    def __init__(
        self,
        container_name: str,
        account_url: Optional[str] = None,
        connection_string: Optional[str] = None,
        credential=None,
        logger: Optional[logging.Logger] = None,
        create_container_if_missing: bool = True,
    ):
        self.container_name = container_name
        self.logger = logger or logging.getLogger(__name__)
        self._service_client = None
        self._container_client = None

        if BlobServiceClient is None:
            self.logger.warning("azure-storage-blob package unavailable. Blob storage is disabled.")
            return

        try:
            if connection_string:
                self._service_client = BlobServiceClient.from_connection_string(connection_string)
            elif account_url and credential is not None:
                self._service_client = BlobServiceClient(account_url=account_url, credential=credential)
            else:
                self.logger.info("Blob storage is not configured. Running in local-only mode.")
                return

            self._container_client = self._service_client.get_container_client(container_name)
            if create_container_if_missing:
                try:
                    self._container_client.create_container()
                except ResourceExistsError:
                    pass
        except Exception as exc:  # pragma: no cover - network/auth dependent
            self.logger.warning("Failed to initialize Blob storage client: %s", exc)
            self._service_client = None
            self._container_client = None

    @classmethod
    def from_settings(
        cls,
        settings: SecuritySettings,
        secret_provider=None,
        logger: Optional[logging.Logger] = None,
    ) -> "BlobStorageManager":
        resolved_logger = logger or logging.getLogger(__name__)

        connection_string = settings.azure_storage_connection_string
        if not connection_string and settings.storage_connection_string_secret_name and secret_provider is not None:
            connection_string = secret_provider.get_secret(settings.storage_connection_string_secret_name)

        credential = None
        if settings.azure_storage_account_url and not connection_string:
            credential = create_azure_credential(prefer_managed_identity=True, logger=resolved_logger)

        return cls(
            container_name=settings.azure_storage_container,
            account_url=settings.azure_storage_account_url,
            connection_string=connection_string,
            credential=credential,
            logger=resolved_logger,
        )

    @property
    def enabled(self) -> bool:
        return self._container_client is not None

    @staticmethod
    def _guess_content_type(path: str) -> Optional[str]:
        guessed_type, _ = mimetypes.guess_type(path)
        return guessed_type

    def upload_file(
        self,
        local_path: str,
        blob_path: str,
        overwrite: bool = True,
        content_type: Optional[str] = None,
    ) -> bool:
        if not self.enabled:
            return False

        if not os.path.exists(local_path):
            self.logger.warning("Cannot upload missing file: %s", local_path)
            return False

        try:
            blob_client = self._container_client.get_blob_client(blob_path)
            upload_kwargs: Dict[str, Any] = {"overwrite": overwrite}

            resolved_content_type = content_type or self._guess_content_type(local_path)
            if resolved_content_type and ContentSettings is not None:
                upload_kwargs["content_settings"] = ContentSettings(content_type=resolved_content_type)

            with open(local_path, "rb") as file_obj:
                blob_client.upload_blob(file_obj, **upload_kwargs)
            return True
        except Exception as exc:  # pragma: no cover - network/auth dependent
            self.logger.warning("Failed to upload %s to blob %s: %s", local_path, blob_path, exc)
            return False

    def download_file(self, blob_path: str, local_path: str, overwrite: bool = False) -> bool:
        if not self.enabled:
            return False

        if os.path.exists(local_path) and not overwrite:
            return False

        try:
            blob_client = self._container_client.get_blob_client(blob_path)
            data = blob_client.download_blob().readall()
        except ResourceNotFoundError:
            self.logger.warning("Blob not found: %s", blob_path)
            return False
        except Exception as exc:  # pragma: no cover - network/auth dependent
            self.logger.warning("Failed to download blob %s: %s", blob_path, exc)
            return False

        target_dir = os.path.dirname(local_path)
        if target_dir:
            os.makedirs(target_dir, exist_ok=True)

        with open(local_path, "wb") as file_obj:
            file_obj.write(data)

        return True

    def append_json_line(self, blob_path: str, payload: Dict[str, Any]) -> bool:
        if not self.enabled:
            return False

        line = json.dumps(payload, ensure_ascii=True, separators=(",", ":")) + "\n"
        line_bytes = line.encode("utf-8")

        blob_client = self._container_client.get_blob_client(blob_path)
        try:
            blob_client.create_append_blob()
        except ResourceExistsError:
            pass
        except Exception:
            # Fallback path for accounts/policies where append blobs are restricted.
            return self._fallback_append(blob_client=blob_client, line_bytes=line_bytes)

        try:
            blob_client.append_block(line_bytes)
            return True
        except Exception:
            return self._fallback_append(blob_client=blob_client, line_bytes=line_bytes)

    def _fallback_append(self, blob_client, line_bytes: bytes) -> bool:
        try:
            try:
                existing = blob_client.download_blob().readall()
            except ResourceNotFoundError:
                existing = b""

            upload_kwargs: Dict[str, Any] = {"overwrite": True}
            if ContentSettings is not None:
                upload_kwargs["content_settings"] = ContentSettings(content_type="application/json")

            blob_client.upload_blob(existing + line_bytes, **upload_kwargs)
            return True
        except Exception as exc:  # pragma: no cover - network/auth dependent
            self.logger.warning("Failed to append blob log: %s", exc)
            return False


class PredictionAuditLogger:
    def __init__(
        self,
        settings: SecuritySettings,
        blob_storage: Optional[BlobStorageManager] = None,
        logger: Optional[logging.Logger] = None,
    ):
        self.settings = settings
        self.blob_storage = blob_storage
        self.logger = logger or logging.getLogger(__name__)

        local_dir = os.path.dirname(self.settings.local_prediction_log_path)
        if local_dir:
            os.makedirs(local_dir, exist_ok=True)

    @staticmethod
    def _hash_text(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def _write_local_json_line(self, payload: Dict[str, Any]) -> None:
        line = json.dumps(payload, ensure_ascii=True) + "\n"
        with open(self.settings.local_prediction_log_path, "a", encoding="utf-8") as log_file:
            log_file.write(line)

    def log_prediction(
        self,
        endpoint: str,
        text: str,
        source: Optional[str],
        is_phishing: bool,
        confidence: float,
        xai_method: Optional[str] = None,
    ) -> None:
        clean_text = (text or "").strip()
        now = datetime.now(timezone.utc)

        payload = {
            "timestamp_utc": now.isoformat(),
            "endpoint": endpoint,
            "source": (source or "unknown"),
            "is_phishing": bool(is_phishing),
            "confidence": round(float(confidence), 2),
            "xai_method": xai_method or "n/a",
            "text_hash_sha256": self._hash_text(clean_text),
            "text_preview": clean_text[:160],
            "text_length": len(clean_text),
            "app_env": self.settings.app_env,
        }

        try:
            self._write_local_json_line(payload)
        except Exception as exc:  # pragma: no cover - filesystem dependent
            self.logger.warning("Failed to write local prediction audit log: %s", exc)

        if not self.settings.blob_prediction_logging_enabled:
            return

        if self.blob_storage is None or not self.blob_storage.enabled:
            return

        blob_path = self.settings.prediction_blob_path(at=now)
        uploaded = self.blob_storage.append_json_line(blob_path=blob_path, payload=payload)
        if not uploaded:
            self.logger.warning("Prediction audit log could not be uploaded to blob path: %s", blob_path)
