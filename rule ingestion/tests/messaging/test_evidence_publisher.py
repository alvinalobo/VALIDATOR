import json
import os

from app.messaging.evidence_publisher import EVIDENCE_TOPIC, EvidencePublisher


class FakeProducer:
    def __init__(self):
        self.calls = []

    def produce(self, topic, value):
        self.calls.append((topic, value))

    def poll(self, timeout):
        return None

    def flush(self, timeout):
        return 0


def test_evidence_publisher_uses_shared_topic(monkeypatch):
    monkeypatch.setenv("KAFKA_EVIDENCE_ENABLED", "true")
    producer = FakeProducer()
    publisher = EvidencePublisher(
        bootstrap_servers="localhost:9092",
        producer=producer,
    )

    event = {
        "event_id": "ev-001",
        "action_id": "act-001",
        "evidence": {"type": "network", "value": "example"},
    }

    publisher.publish_evidence(event)

    assert len(producer.calls) == 1
    topic, payload = producer.calls[0]

    assert topic == "cybreach.evidence.v1"
    assert json.loads(payload.decode("utf-8")) == event


def test_evidence_topic_constant_matches_contract():
    assert EVIDENCE_TOPIC == "cybreach.evidence.v1"
