import json
import os
from typing import Any, Dict, Optional


EVIDENCE_TOPIC = "cybreach.evidence.v1"


class EvidencePublisher:
    """Publishes evidence events to the shared Module 2 Kafka topic."""

    def __init__(
        self,
        bootstrap_servers: Optional[str] = None,
        producer: Optional[object] = None,
    ):
        self.enabled = os.getenv("KAFKA_EVIDENCE_ENABLED", "false").lower() == "true"
        self.bootstrap_servers = (
            bootstrap_servers
            or os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
        )
# The Kafka client is only required when publishing is actually enabled
        # (and always injectable for tests). Keeping the import lazy means a CI
        # box or a lint/test run without the client library still boots the app.
        if producer is None and self.enabled:
            from confluent_kafka import Producer

            producer = Producer({"bootstrap.servers": self.bootstrap_servers})
        self._producer = producer

    def publish_evidence(self, event: Dict[str, Any]) -> None:
        """Publish one evidence event as JSON when Kafka publishing is enabled."""
        if self._producer is None:
            return

        payload = json.dumps(
            event,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        self._producer.produce(
            EVIDENCE_TOPIC,
            value=payload,
        )
        self._producer.poll(0)

    def flush(self, timeout: float = 10.0) -> int:
        """Flush pending events and return the number still outstanding."""
        if not self.enabled or self._producer is None:
            return 0
        return self._producer.flush(timeout)
