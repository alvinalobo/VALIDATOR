import json
import os
from typing import Any, Dict, Optional

from confluent_kafka import Producer


EVIDENCE_TOPIC = "cybreach.evidence.v1"


class EvidencePublisher:
    """Publishes evidence events to the shared Module 2 Kafka topic."""

    def __init__(
        self,
        bootstrap_servers: Optional[str] = None,
        producer: Optional[Producer] = None,
    ):
        self.enabled = os.getenv("KAFKA_EVIDENCE_ENABLED", "false").lower() == "true"
        self.bootstrap_servers = (
            bootstrap_servers
            or os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
        )
        self._producer = (
            producer or Producer({"bootstrap.servers": self.bootstrap_servers})
            if self.enabled
            else None
        )

    def publish_evidence(self, event: Dict[str, Any]) -> None:
        """Publish one evidence event as JSON when Kafka publishing is enabled."""
        if not self.enabled or self._producer is None:
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
