from typing import Optional
import logging

try:
    from azure.identity import (
        AzureCliCredential,
        ChainedTokenCredential,
        EnvironmentCredential,
        ManagedIdentityCredential,
    )
except Exception:  # pragma: no cover - optional dependency
    AzureCliCredential = None
    ChainedTokenCredential = None
    EnvironmentCredential = None
    ManagedIdentityCredential = None


def create_azure_credential(
    prefer_managed_identity: bool = True,
    logger: Optional[logging.Logger] = None,
):
    if ChainedTokenCredential is None:
        if logger is not None:
            logger.warning("azure-identity package unavailable. Cloud authentication is disabled.")
        return None

    providers = []

    if prefer_managed_identity and ManagedIdentityCredential is not None:
        providers.append(ManagedIdentityCredential())

    if EnvironmentCredential is not None:
        providers.append(EnvironmentCredential())

    if AzureCliCredential is not None:
        providers.append(AzureCliCredential())

    if not providers:
        if logger is not None:
            logger.warning("No Azure credential providers are available.")
        return None

    if len(providers) == 1:
        return providers[0]

    return ChainedTokenCredential(*providers)
