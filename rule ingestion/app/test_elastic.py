from app.connector.elastic_connector import ElasticConnector
from app.connector.base_connector import ConnectorConfig

config = ConnectorConfig(
    connector_id="test",
    vendor="elastic",
    product="elastic",
    credentials={"base_url": "https://your-elastic-host:9200", "api_key": "your-key"},
    scope={"index": "logs-*"},
)

connector = ElasticConnector(config)
print("Connector created successfully:", connector)
