import os

from cryptography.fernet import Fernet

from app.connector.base_connector import ConnectorConfig
from app.connector.credential_manager import CredentialManager
from app.connector.splunk_connector import SplunkConnector


def test_splunk_token_is_decrypted_on_demand():
    key = Fernet.generate_key()
    os.environ["CONNECTOR_ENCRYPTION_KEY"] = key.decode()

    manager = CredentialManager()
    plaintext_token = "test-token"
    encrypted_token = manager.encrypt(plaintext_token)

    config = ConnectorConfig(
        connector_id="splunk-security-test",
        vendor="splunk",
        product="siem",
        credentials={
            "host": "http://splunk-test",
            "port": 8089,
            "token": encrypted_token,
            "mock": False,
        },
    )

    connector = SplunkConnector(config)

    assert encrypted_token.startswith("enc:v1:")
    assert config.credentials["token"] == encrypted_token
    assert not hasattr(connector, "token")

    assert connector.get_credential("token") == plaintext_token

    del os.environ["CONNECTOR_ENCRYPTION_KEY"]


def test_plaintext_credential_remains_compatible_without_encryption():
    os.environ.pop("CONNECTOR_ENCRYPTION_KEY", None)

    config = ConnectorConfig(
        connector_id="splunk-plaintext-test",
        vendor="splunk",
        product="siem",
        credentials={
            "host": "http://splunk-test",
            "port": 8089,
            "token": "test-token",
            "mock": False,
        },
    )

    connector = SplunkConnector(config)

    assert connector.get_credential("token") == "test-token"
    assert not hasattr(connector, "token")


def test_connector_secrets_are_not_stored_as_instance_attributes(monkeypatch):
    key = Fernet.generate_key()
    monkeypatch.setenv("CONNECTOR_ENCRYPTION_KEY", key.decode())

    manager = CredentialManager()

    encrypted = {
        "token": manager.encrypt("secret-token"),
        "password": manager.encrypt("secret-password"),
        "api_key": manager.encrypt("secret-api-key"),
        "sec_token": manager.encrypt("secret-sec-token"),
        "client_secret": manager.encrypt("secret-client-secret"),
        "access_token": manager.encrypt("secret-access-token"),
    }

    config = ConnectorConfig(
        connector_id="security-audit-test",
        vendor="splunk",
        product="siem",
        credentials={
            "host": "http://splunk-test",
            "port": 8089,
            "token": encrypted["token"],
            "password": encrypted["password"],
            "mock": False,
        },
    )

    connector = SplunkConnector(config)

    assert not hasattr(connector, "token")
    assert not hasattr(connector, "password")

    stored_values = vars(connector).values()

    assert encrypted["token"] not in stored_values
    assert encrypted["password"] not in stored_values
    assert "secret-token" not in stored_values
    assert "secret-password" not in stored_values
