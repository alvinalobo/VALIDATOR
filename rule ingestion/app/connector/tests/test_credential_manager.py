import pytest
from cryptography.fernet import Fernet

from app.connector.credential_manager import CredentialManager


def test_encrypt_and_decrypt():
    manager = CredentialManager(Fernet.generate_key())

    encrypted = manager.encrypt("test-secret")
    
    assert encrypted != "test-secret"
    assert manager.decrypt(encrypted) == "test-secret"


def test_wrong_key_cannot_decrypt():
    manager = CredentialManager(Fernet.generate_key())
    wrong_manager = CredentialManager(Fernet.generate_key())

    encrypted = manager.encrypt("test-secret")

    with pytest.raises(ValueError, match="Unable to decrypt credential value"):
        wrong_manager.decrypt(encrypted)


def test_missing_encryption_key_is_rejected(monkeypatch):
    monkeypatch.delenv("CONNECTOR_ENCRYPTION_KEY", raising=False)

    with pytest.raises(ValueError, match="environment variable is required"):
        CredentialManager()


def test_invalid_encryption_key_is_rejected():
    with pytest.raises(ValueError, match="Invalid connector encryption key"):
        CredentialManager(b"invalid-key")


def test_none_credential_is_rejected():
    manager = CredentialManager(Fernet.generate_key())

    with pytest.raises(ValueError, match="Credential value cannot be None"):
        manager.encrypt(None)


def test_empty_encrypted_value_is_rejected():
    manager = CredentialManager(Fernet.generate_key())

    with pytest.raises(
        ValueError,
        match="Encrypted credential value cannot be empty",
    ):
        manager.decrypt("")
