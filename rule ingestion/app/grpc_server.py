"""
Alpha gRPC Server: RuleIngestService Implementation

Provides gRPC endpoints for inter-pod communication:
  - FetchRules: Beta (Validation Engine) queries rules
  - GetRule: Delta (Verdict Publisher) fetches rule metadata
  - HealthCheck: All pods probe rule store health

Invoked from main.py startup or as a sidecar thread.
Proto contract: rule ingestion/proto/cybreach_service.proto
"""

import time
from concurrent import futures
from typing import List, Optional, Dict, Any

import grpc
from proto import cybreach_service_pb2, cybreach_service_pb2_grpc


class RuleIngestServiceServicer(cybreach_service_pb2_grpc.RuleIngestServiceServicer):
    """
    Implements the RuleIngestService gRPC endpoints.
    Wraps the existing rule_versioning and rule querying logic.
    """

    def __init__(self, rule_store: Optional[Any] = None):
        """
        Args:
            rule_store: The existing rule store/versioning service from main.py.
                       If None, lazily imported from app.services.
        """
        self.rule_store = rule_store

    def FetchRules(
        self, request: cybreach_service_pb2.RuleQueryRequest, context
    ) -> cybreach_service_pb2.RuleQueryResponse:
        """
        Fetch rules matching a query, with limit.
        Maps to: existing API GET /api/v2/rules endpoint or database lookup.
        """
        try:
            # Lazy import to avoid circular dependencies
            if not self.rule_store:
                from app.services.rule_versioning import rule_versioning_service
                self.rule_store = rule_versioning_service

            # Get all rules (simplified; in production, filter by rule_query)
            all_rule_ids = self.rule_store.all_rule_ids()
            rules_to_return = []

            # Apply limit
            limit = request.limit if request.limit > 0 else 50
            for rule_id in all_rule_ids[:limit]:
                latest = self.rule_store.get_latest(rule_id)
                if latest:
                    rules_to_return.append(
                        cybreach_service_pb2.RuleDetail(
                            rule_id=latest.rule_id,
                            rule_name=latest.title,
                            rule_query=latest.rule_id,  # Placeholder
                            source="ingestion",
                            created_at=int(time.time()),
                            updated_at=int(time.time()),
                        )
                    )

            return cybreach_service_pb2.RuleQueryResponse(
                rules=rules_to_return,
                status="ok",
            )

        except Exception as e:
            context.abort(
                grpc.StatusCode.INTERNAL, f"Failed to fetch rules: {str(e)}"
            )

    def GetRule(
        self, request: cybreach_service_pb2.GetRuleRequest, context
    ) -> cybreach_service_pb2.RuleDetail:
        """
        Fetch a single rule by rule_id.
        Maps to: existing API GET /api/v2/rules/{rule_id} endpoint.
        """
        try:
            if not self.rule_store:
                from app.services.rule_versioning import rule_versioning_service
                self.rule_store = rule_versioning_service

            latest = self.rule_store.get_latest(request.rule_id)
            if not latest:
                context.abort(
                    grpc.StatusCode.NOT_FOUND,
                    f"Rule '{request.rule_id}' not found",
                )

            return cybreach_service_pb2.RuleDetail(
                rule_id=latest.rule_id,
                rule_name=latest.title,
                rule_query=latest.rule_id,
                source="ingestion",
                created_at=int(time.time()),
                updated_at=int(time.time()),
            )

        except Exception as e:
            context.abort(
                grpc.StatusCode.INTERNAL, f"Failed to get rule: {str(e)}"
            )

    def HealthCheck(
        self, request: cybreach_service_pb2.HealthRequest, context
    ) -> cybreach_service_pb2.HealthResponse:
        """
        Health check for the rule store.
        Returns: status="ok" if database is reachable, else "degraded".
        """
        try:
            if not self.rule_store:
                from app.services.rule_versioning import rule_versioning_service
                self.rule_store = rule_versioning_service

            # Perform a simple query to check if rule store is alive
            _ = self.rule_store.all_rule_ids()

            return cybreach_service_pb2.HealthResponse(
                status="ok",
                service="alpha-rule-ingestion",
                timestamp=int(time.time()),
                version="1.0",
            )
        except Exception:
            return cybreach_service_pb2.HealthResponse(
                status="degraded",
                service="alpha-rule-ingestion",
                timestamp=int(time.time()),
                version="1.0",
            )


def serve(host: str = "0.0.0.0", port: int = 50051):
    """
    Start the gRPC server on the given host:port.
    
    Typical usage in FastAPI startup:
        import threading
        grpc_thread = threading.Thread(
            target=lambda: grpc_server.serve(), daemon=True
        )
        grpc_thread.start()
    
    Args:
        host: Bind address (default 0.0.0.0)
        port: Bind port (default 50051)
    """
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    cybreach_service_pb2_grpc.add_RuleIngestServiceServicer_to_server(
        RuleIngestServiceServicer(), server
    )
    server.add_insecure_port(f"{host}:{port}")
    server.start()
    print(f"[Alpha gRPC] RuleIngestService listening on {host}:{port}")
    server.wait_for_termination()


if __name__ == "__main__":
    serve()
