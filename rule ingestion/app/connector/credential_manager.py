import os
from typing import Any

from cryptography.fernet import Fernet, InvalidToken


class CredentialManager:
    """Encrypt and decrypt connector credential values."""

    ENV_KEY_NAME = "CONNECTOR_ENCRYPTION_KEY"
    ENCRYPTED_PREFIX = "enc:v1:"

    def __init__(self, key: bytes | None = None):
        encryption_key = key or os.getenv(self.ENV_KEY_NAME)

        if not encryption_key:
            raise ValueError(
                f"{self.ENV_KEY_NAME} environment variable is required"
            )

        if isinstance(encryption_key, str):
            encryption_key = encryption_key.encode()

        try:
            self._fernet = Fernet(encryption_key)
        except (ValueError, TypeError) as exc:
            raise ValueError("Invalid connector encryption key") from exc

    def encrypt(self, value: Any) -> str:
        """Encrypt a credential value and return protected ciphertext."""
        if value is None:
            raise ValueError("Credential value cannot be None")

        encrypted = self._fernet.encrypt(
            str(value).encode()
        ).decode()

        return f"{self.ENCRYPTED_PREFIX}{encrypted}"

    def decrypt(self, encrypted_value: str) -> str:
        """Decrypt a protected credential value."""
        if not encrypted_value:
            raise ValueError("Encrypted credential value cannot be empty")

        if not encrypted_value.startswith(self.ENCRYPTED_PREFIX):
            raise ValueError("Credential value is not encrypted")

        ciphertext = encrypted_value[len(self.ENCRYPTED_PREFIX):]

        try:
            return self._fernet.decrypt(
                ciphertext.encode()
            ).decode()
        except (InvalidToken, ValueError, TypeError) as exc:
            raise ValueError(
                "Unable to decrypt credential value"
            ) from exc

    def is_encrypted(self, value: Any) -> bool:
        """Return whether a value uses the protected credential format."""
        return (
            isinstance(value, str)
            and value.startswith(self.ENCRYPTED_PREFIX)
        )
