from typing import Dict, Optional
import logging
import os
import threading

from src.security.config import SecuritySettings
from src.security.identity import create_azure_credential

try:
    from azure.keyvault.secrets import SecretClient
except Exception:  # pragma: no cover - optional dependency
    SecretClient = None


class KeyVaultSecretProvider:
    def __init__(
        self,
        vault_url: Optional[str],
        credential=None,
        logger: Optional[logging.Logger] = None,
        required: bool = False,
    ):
        self.vault_url = vault_url
        self.required = required
        self.logger = logger or logging.getLogger(__name__)
        self._cache: Dict[str, str] = {}
        self._cache_lock = threading.Lock()
        self._client = None

        if not vault_url:
            if required:
                raise RuntimeError("AZURE_KEY_VAULT_URL is required but not configured.")
            return

        if SecretClient is None:
            if required:
                raise RuntimeError("azure-keyvault-secrets package is required but not installed.")
            self.logger.warning("azure-keyvault-secrets package unavailable. Secret fetch is disabled.")
            return

        if credential is None:
            if required:
                raise RuntimeError("No Azure credential available for Key Vault authentication.")
            self.logger.warning("No Azure credential available. Secret fetch is disabled.")
            return

        self._client = SecretClient(vault_url=vault_url, credential=credential)

    @classmethod
    def from_settings(
        cls,
        settings: SecuritySettings,
        logger: Optional[logging.Logger] = None,
    ) -> "KeyVaultSecretProvider":
        auth_logger = logger or logging.getLogger(__name__)
        credential = None
        if settings.azure_key_vault_url:
            credential = create_azure_credential(prefer_managed_identity=True, logger=auth_logger)
        return cls(
            vault_url=settings.azure_key_vault_url,
            credential=credential,
            logger=auth_logger,
            required=settings.require_key_vault,
        )

    @property
    def enabled(self) -> bool:
        return self._client is not None

    def get_secret(
        self,
        secret_name: Optional[str],
        default: Optional[str] = None,
        required: bool = False,
    ) -> Optional[str]:
        if not secret_name:
            return default

        clean_name = secret_name.strip()
        if not clean_name:
            return default

        with self._cache_lock:
            if clean_name in self._cache:
                return self._cache[clean_name]

        if self._client is None:
            if required or self.required:
                raise RuntimeError(f"Key Vault client unavailable while secret '{clean_name}' is required.")
            return default

        try:
            value = self._client.get_secret(clean_name).value
        except Exception as exc:  # pragma: no cover - network/auth dependent
            if required or self.required:
                raise RuntimeError(f"Failed to retrieve required secret '{clean_name}': {exc}") from exc
            self.logger.warning("Failed to retrieve secret '%s': %s", clean_name, exc)
            return default

        with self._cache_lock:
            self._cache[clean_name] = value

        return value

    def load_environment_secrets(self, mapping: Dict[str, str], overwrite: bool = False) -> Dict[str, str]:
        loaded: Dict[str, str] = {}
        if not mapping:
            return loaded

        for env_name, secret_name in mapping.items():
            if not overwrite and os.getenv(env_name):
                continue

            value = self.get_secret(secret_name)
            if value is None:
                continue

            os.environ[env_name] = value
            loaded[env_name] = secret_name

        return loaded
