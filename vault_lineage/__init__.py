"""VaultLineage: Envelope-Encrypted AI Event Store, ML Opt-Out Gate & Crypto-Shred Deletion Engine."""

from .storage_engine import (
     CONSENT_POLICIES,
     PURPOSE_POLICIES,
     CryptoShreddedError,
     AuthorizationDeniedError,
     VaultLineageEngine,
)

__all__ = [
    "CONSENT_POLICIES",
    "PURPOSE_POLICIES",
    "CryptoShreddedError",
    "AuthorizationDeniedError",
    "VaultLineageEngine",
]
__version__ = "1.0.0"
