"""
GraphQL JWT Test Module - GraphQL endpoint JWT injection and
field-level permission analysis.

This module provides:
    1. GraphQL endpoint identification
    2. JWT injection in GraphQL queries
    3. Batch query analysis with different permission JWTs
    4. Field-level permission control detection
    5. GraphQL introspection-based permission testing

Integration points:
    - JWT Editor module
    - OAuth Analyzer module
    - MITM proxy traffic capture
    - Report generation engine

Author: Kunlun Security Lab
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

import aiohttp

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================

class GraphQLTestType(str, Enum):
    """GraphQL test types."""

    JWT_INJECTION = "jwt_injection"
    FIELD_PERMISSION = "field_permission"
    INTROSPECTION = "introspection"
    BATCH_COMPARISON = "batch_comparison"
    MUTATION_PERMISSION = "mutation_permission"


class Severity(str, Enum):
    """Vulnerability severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class GraphQLField:
    """GraphQL field representation.

    Attributes:
        name: Field name
        type_name: Field type
        is_deprecated: Whether field is deprecated
        description: Field description
        requires_auth: Whether field requires authentication
        permission_level: Required permission level
    """

    name: str = ""
    type_name: str = ""
    is_deprecated: bool = False
    description: str = ""
    requires_auth: bool = False
    permission_level: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "name": self.name,
            "type_name": self.type_name,
            "is_deprecated": self.is_deprecated,
            "description": self.description,
            "requires_auth": self.requires_auth,
            "permission_level": self.permission_level,
        }


@dataclass
class GraphQLTestResult:
    """GraphQL test result.

    Attributes:
        test_type: Type of test performed
        query: GraphQL query used
        jwt_used: JWT token identifier
        success: Whether test succeeded
        severity: Result severity
        data_accessible: Whether data was accessible
        fields_tested: Number of fields tested
        fields_accessible: Number of accessible fields
        response_data: Response data
        evidence: Evidence of vulnerability
        timestamp: Result timestamp
    """

    test_type: GraphQLTestType = GraphQLTestType.JWT_INJECTION
    query: str = ""
    jwt_used: str = ""
    success: bool = False
    severity: Severity = Severity.INFO
    data_accessible: bool = False
    fields_tested: int = 0
    fields_accessible: int = 0
    response_data: Dict[str, Any] = field(default_factory=dict)
    evidence: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "test_type": self.test_type.value,
            "query": self.query,
            "jwt_used": self.jwt_used,
            "success": self.success,
            "severity": self.severity.value,
            "data_accessible": self.data_accessible,
            "fields_tested": self.fields_tested,
            "fields_accessible": self.fields_accessible,
            "response_data": self.response_data,
            "evidence": self.evidence,
            "timestamp": self.timestamp,
        }


@dataclass
class FieldPermissionMap:
    """Field-level permission mapping.

    Attributes:
        field_name: Field name
        permission_levels: Dictionary of JWT role to access status
    """

    field_name: str = ""
    permission_levels: Dict[str, bool] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "field_name": self.field_name,
            "permission_levels": self.permission_levels,
        }


# =============================================================================
# GraphQL Endpoint Detector
# =============================================================================

class GraphQLEndpointDetector:
    """Detects GraphQL endpoints in target applications.

    Common GraphQL endpoint patterns:
    - /graphql
    - /graphql/console
    - /api/graphql
    - /graphiql
    - /playground
    """

    COMMON_ENDPOINTS = [
        "/graphql",
        "/graphql/console",
        "/api/graphql",
        "/graphiql",
        "/playground",
        "/api/v1/graphql",
        "/api/v2/graphql",
        "/query",
        "/api/query",
    ]

    INTROSPECTION_QUERY = """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          ...FullType
        }
        directives {
          name
          description
          locations
          args {
            ...InputValue
          }
        }
      }
    }

    fragment FullType on __Type {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          ...InputValue
        }
        type {
          ...TypeRef
        }
        isDeprecated
        deprecationReason
      }
    }

    fragment InputValue on __InputValue {
      name
      description
      type {
        ...TypeRef
      }
      defaultValue
    }

    fragment TypeRef on __Type {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                    ofType {
                      kind
                      name
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
    """

    def __init__(self, base_url: str) -> None:
        """Initialize the GraphQL endpoint detector.

        Args:
            base_url: Target base URL.
        """
        self.base_url = base_url
        self.discovered_endpoints: List[str] = []

    async def detect_endpoints(
        self,
        timeout: int = 10,
    ) -> List[str]:
        """Detect GraphQL endpoints.

        Args:
            timeout: Request timeout in seconds.

        Returns:
            List of discovered GraphQL endpoint URLs.
        """
        found_endpoints: List[str] = []

        async with aiohttp.ClientSession() as session:
            for endpoint in self.COMMON_ENDPOINTS:
                url = f"{self.base_url.rstrip('/')}{endpoint}"

                try:
                    async with session.post(
                        url,
                        json={"query": "{ __typename }"},
                        timeout=timeout,
                    ) as response:
                        if response.status == 200:
                            body = await response.text()
                            if "__typename" in body or "data" in body:
                                found_endpoints.append(url)
                                logger.info(f"GraphQL endpoint found: {url}")

                except Exception:
                    continue

        self.discovered_endpoints = found_endpoints
        return found_endpoints

    async def test_introspection(
        self,
        endpoint: str,
        timeout: int = 10,
    ) -> Optional[Dict[str, Any]]:
        """Test if introspection is enabled.

        Args:
            endpoint: GraphQL endpoint URL.
            timeout: Request timeout in seconds.

        Returns:
            Introspection result if enabled.
        """
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    endpoint,
                    json={"query": self.INTROSPECTION_QUERY},
                    timeout=timeout,
                ) as response:
                    if response.status == 200:
                        body = await response.text()
                        result: Dict[str, Any] = json.loads(body)
                        return result

        except Exception as e:
            logger.error(f"Introspection test failed: {e}")

        return None


# =============================================================================
# GraphQL JWT Injection Tester
# =============================================================================

class GraphQLJWTInjectionTester:
    """Tests JWT injection in GraphQL queries.

    Tests:
    - JWT in Authorization header
    - JWT in query variables
    - JWT in cookies
    - JWT in custom headers
    """

    def __init__(
        self,
        graphql_endpoint: str,
        jwt_tokens: Dict[str, str],
    ) -> None:
        """Initialize the GraphQL JWT injection tester.

        Args:
            graphql_endpoint: GraphQL endpoint URL.
            jwt_tokens: Dictionary of role name to JWT token.
        """
        self.graphql_endpoint = graphql_endpoint
        self.jwt_tokens = jwt_tokens
        self.results: List[GraphQLTestResult] = []

    async def test_jwt_in_header(
        self,
        query: str,
        timeout: int = 10,
    ) -> List[GraphQLTestResult]:
        """Test JWT in Authorization header.

        Args:
            query: GraphQL query to test.
            timeout: Request timeout in seconds.

        Returns:
            List of GraphQLTestResult.
        """
        results: List[GraphQLTestResult] = []

        for role, token in self.jwt_tokens.items():
            result = GraphQLTestResult(
                test_type=GraphQLTestType.JWT_INJECTION,
                query=query,
                jwt_used=role,
                timestamp=time.time(),
            )

            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        self.graphql_endpoint,
                        json={"query": query},
                        headers={"Authorization": f"Bearer {token}"},
                        timeout=timeout,
                    ) as response:
                        body = await response.text()
                        result.response_data = json.loads(body) if body else {}
                        result.success = response.status == 200
                        result.data_accessible = "errors" not in result.response_data

                        if result.data_accessible:
                            result.severity = Severity.INFO
                        else:
                            result.severity = Severity.LOW

            except Exception as e:
                result.evidence["error"] = str(e)

            results.append(result)
            self.results.append(result)

        return results

    async def test_jwt_in_variables(
        self,
        query: str,
        timeout: int = 10,
    ) -> List[GraphQLTestResult]:
        """Test JWT in query variables.

        Args:
            query: GraphQL query to test.
            timeout: Request timeout in seconds.

        Returns:
            List of GraphQLTestResult.
        """
        results: List[GraphQLTestResult] = []

        for role, token in self.jwt_tokens.items():
            result = GraphQLTestResult(
                test_type=GraphQLTestType.JWT_INJECTION,
                query=query,
                jwt_used=role,
                timestamp=time.time(),
            )

            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        self.graphql_endpoint,
                        json={
                            "query": query,
                            "variables": {"auth_token": token},
                        },
                        timeout=timeout,
                    ) as response:
                        body = await response.text()
                        result.response_data = json.loads(body) if body else {}
                        result.success = response.status == 200
                        result.data_accessible = "errors" not in result.response_data

            except Exception as e:
                result.evidence["error"] = str(e)

            results.append(result)
            self.results.append(result)

        return results


# =============================================================================
# GraphQL Field Permission Analyzer
# =============================================================================

class GraphQLFieldPermissionAnalyzer:
    """Analyzes field-level permissions in GraphQL APIs.

    Tests:
    - Which fields are accessible with different JWT roles
    - Field-level authorization bypass
    - Introspection-based permission mapping
    """

    SENSITIVE_FIELDS = [
        "password",
        "secret",
        "token",
        "apiKey",
        "creditCard",
        "ssn",
        "email",
        "phone",
        "address",
        "role",
        "permissions",
        "isAdmin",
        "isSuperuser",
    ]

    def __init__(
        self,
        graphql_endpoint: str,
        jwt_tokens: Dict[str, str],
    ) -> None:
        """Initialize the field permission analyzer.

        Args:
            graphql_endpoint: GraphQL endpoint URL.
            jwt_tokens: Dictionary of role name to JWT token.
        """
        self.graphql_endpoint = graphql_endpoint
        self.jwt_tokens = jwt_tokens
        self.field_permissions: Dict[str, FieldPermissionMap] = {}
        self.results: List[GraphQLTestResult] = []

    async def analyze_field_permissions(
        self,
        fields: List[str],
        timeout: int = 10,
    ) -> Dict[str, FieldPermissionMap]:
        """Analyze field-level permissions.

        Args:
            fields: List of field names to test.
            timeout: Request timeout in seconds.

        Returns:
            Dictionary of field name to permission map.
        """
        for field_name in fields:
            perm_map = FieldPermissionMap(field_name=field_name)

            for role, token in self.jwt_tokens.items():
                query = f"{{ {field_name} }}"

                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.post(
                            self.graphql_endpoint,
                            json={"query": query},
                            headers={"Authorization": f"Bearer {token}"},
                            timeout=timeout,
                        ) as response:
                            body = await response.text()
                            data = json.loads(body) if body else {}
                            has_errors = "errors" in data
                            perm_map.permission_levels[role] = not has_errors

                except Exception:
                    perm_map.permission_levels[role] = False

            self.field_permissions[field_name] = perm_map

        return self.field_permissions

    async def detect_permission_bypasses(
        self,
        timeout: int = 10,
    ) -> List[GraphQLTestResult]:
        """Detect field-level permission bypasses.

        Args:
            timeout: Request timeout in seconds.

        Returns:
            List of GraphQLTestResult for bypasses found.
        """
        bypasses: List[GraphQLTestResult] = []

        for field_name, perm_map in self.field_permissions.items():
            levels = perm_map.permission_levels

            has_admin = levels.get("admin", False)
            has_user = levels.get("user", False)
            has_guest = levels.get("guest", False)
            has_unauthenticated = levels.get("unauthenticated", False)

            if field_name in self.SENSITIVE_FIELDS:
                if has_user or has_guest or has_unauthenticated:
                    result = GraphQLTestResult(
                        test_type=GraphQLTestType.FIELD_PERMISSION,
                        query=f"{{ {field_name} }}",
                        jwt_used="low-privilege",
                        success=True,
                        severity=Severity.CRITICAL,
                        data_accessible=True,
                        fields_tested=1,
                        fields_accessible=1,
                        evidence={
                            "field": field_name,
                            "accessible_by": [
                                role for role, accessible in levels.items() if accessible
                            ],
                        },
                        timestamp=time.time(),
                    )
                    bypasses.append(result)
                    self.results.append(result)

        return bypasses

    async def test_introspection_with_jwt(
        self,
        timeout: int = 10,
    ) -> List[GraphQLField]:
        """Test introspection with different JWT roles.

        Args:
            timeout: Request timeout in seconds.

        Returns:
            List of discovered GraphQLField.
        """
        all_fields: List[GraphQLField] = []

        for role, token in self.jwt_tokens.items():
            introspection_query = """
            {
              __schema {
                queryType {
                  fields {
                    name
                    type { name kind }
                  }
                }
              }
            }
            """

            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        self.graphql_endpoint,
                        json={"query": introspection_query},
                        headers={"Authorization": f"Bearer {token}"},
                        timeout=timeout,
                    ) as response:
                        body = await response.text()
                        data = json.loads(body) if body else {}

                        if "data" in data and "errors" not in data:
                            schema = data["data"].get("__schema", {})
                            query_type = schema.get("queryType", {})
                            fields = query_type.get("fields", [])

                            for f in fields:
                                field_obj = GraphQLField(
                                    name=f["name"],
                                    type_name=f.get("type", {}).get("name", ""),
                                    requires_auth=role != "unauthenticated",
                                    permission_level=role,
                                )
                                all_fields.append(field_obj)

            except Exception as e:
                logger.error(f"Introspection with {role} failed: {e}")

        return all_fields


# =============================================================================
# GraphQL Batch Comparison Tester
# =============================================================================

class GraphQLBatchComparisonTester:
    """Tests GraphQL queries with multiple JWT tokens for comparison.

    Identifies:
    - Data differences between roles
    - Unauthorized data access
    - Missing field-level authorization
    """

    def __init__(
        self,
        graphql_endpoint: str,
        jwt_tokens: Dict[str, str],
    ) -> None:
        """Initialize the batch comparison tester.

        Args:
            graphql_endpoint: GraphQL endpoint URL.
            jwt_tokens: Dictionary of role name to JWT token.
        """
        self.graphql_endpoint = graphql_endpoint
        self.jwt_tokens = jwt_tokens
        self.results: List[GraphQLTestResult] = []

    async def run_batch_comparison(
        self,
        queries: List[str],
        timeout: int = 10,
    ) -> List[GraphQLTestResult]:
        """Run batch comparison tests.

        Args:
            queries: List of GraphQL queries to test.
            timeout: Request timeout in seconds.

        Returns:
            List of GraphQLTestResult.
        """
        results: List[GraphQLTestResult] = []

        for query in queries:
            role_responses: Dict[str, Dict[str, Any]] = {}

            async with aiohttp.ClientSession() as session:
                for role, token in self.jwt_tokens.items():
                    try:
                        async with session.post(
                            self.graphql_endpoint,
                            json={"query": query},
                            headers={"Authorization": f"Bearer {token}"},
                            timeout=timeout,
                        ) as response:
                            body = await response.text()
                            role_responses[role] = (
                                json.loads(body) if body else {}
                            )
                    except Exception:
                        role_responses[role] = {"error": "request_failed"}

            comparison_result = self._compare_responses(role_responses)

            result = GraphQLTestResult(
                test_type=GraphQLTestType.BATCH_COMPARISON,
                query=query,
                success=comparison_result["has_differences"],
                severity=(
                    Severity.HIGH
                    if comparison_result["has_differences"]
                    else Severity.INFO
                ),
                response_data=comparison_result,
                evidence={"role_responses": role_responses},
                timestamp=time.time(),
            )

            results.append(result)
            self.results.append(result)

        return results

    def _compare_responses(
        self,
        responses: Dict[str, Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Compare responses from different roles.

        Args:
            responses: Dictionary of role to response data.

        Returns:
            Comparison result dictionary.
        """
        has_differences = False
        differences: Dict[str, Any] = {}

        roles = list(responses.keys())

        for i in range(len(roles)):
            for j in range(i + 1, len(roles)):
                role_a = roles[i]
                role_b = roles[j]

                resp_a = responses.get(role_a, {})
                resp_b = responses.get(role_b, {})

                if resp_a != resp_b:
                    has_differences = True
                    differences[f"{role_a}_vs_{role_b}"] = {
                        "role_a_has": self._get_data_keys(resp_a),
                        "role_b_has": self._get_data_keys(resp_b),
                    }

        return {
            "has_differences": has_differences,
            "differences": differences,
            "roles_tested": len(roles),
        }

    def _get_data_keys(self, response: Dict[str, Any]) -> List[str]:
        """Extract data keys from response.

        Args:
            response: GraphQL response.

        Returns:
            List of data keys.
        """
        data = response.get("data", {})
        if isinstance(data, dict):
            return list(data.keys())
        return []


# =============================================================================
# Main GraphQL JWT Test Manager
# =============================================================================

class GraphQLJWTTestManager:
    """Main GraphQL JWT testing coordination engine.

    Integrates endpoint detection, JWT injection testing,
    field permission analysis, and batch comparison.

    Attributes:
        base_url: Target base URL
    """

    def __init__(self, base_url: str) -> None:
        """Initialize the GraphQL JWT test manager.

        Args:
            base_url: Target base URL.
        """
        self.base_url = base_url
        self.endpoint_detector = GraphQLEndpointDetector(base_url)

    async def discover_graphql_endpoints(
        self,
        timeout: int = 10,
    ) -> List[str]:
        """Discover GraphQL endpoints.

        Args:
            timeout: Request timeout in seconds.

        Returns:
            List of discovered endpoint URLs.
        """
        return await self.endpoint_detector.detect_endpoints(timeout)

    async def run_full_jwt_test_suite(
        self,
        graphql_endpoint: str,
        jwt_tokens: Dict[str, str],
        test_queries: Optional[List[str]] = None,
        timeout: int = 10,
    ) -> Dict[str, Any]:
        """Run full GraphQL JWT test suite.

        Args:
            graphql_endpoint: GraphQL endpoint URL.
            jwt_tokens: Dictionary of role name to JWT token.
            test_queries: Optional list of test queries.
            timeout: Request timeout in seconds.

        Returns:
            Dictionary with test results.
        """
        injection_tester = GraphQLJWTInjectionTester(
            graphql_endpoint, jwt_tokens
        )
        field_analyzer = GraphQLFieldPermissionAnalyzer(
            graphql_endpoint, jwt_tokens
        )
        batch_tester = GraphQLBatchComparisonTester(
            graphql_endpoint, jwt_tokens
        )

        default_queries = [
            "{ __typename }",
            "{ viewer { id email role } }",
            "{ users { id email role } }",
        ]

        queries = test_queries or default_queries

        all_results: Dict[str, Any] = {
            "endpoint": graphql_endpoint,
            "jwt_roles": list(jwt_tokens.keys()),
            "injection_tests": [],
            "field_permission_tests": [],
            "batch_comparison_tests": [],
            "permission_bypasses": [],
        }

        for query in queries:
            injection_results = await injection_tester.test_jwt_in_header(
                query, timeout
            )
            all_results["injection_tests"].extend(
                [r.to_dict() for r in injection_results]
            )

        if test_queries:
            field_perms = await field_analyzer.analyze_field_permissions(
                ["id", "email", "role", "password", "token"], timeout
            )
            all_results["field_permission_tests"] = {
                k: v.to_dict() for k, v in field_perms.items()
            }

            bypasses = await field_analyzer.detect_permission_bypasses(timeout)
            all_results["permission_bypasses"] = [
                r.to_dict() for r in bypasses
            ]

        batch_results = await batch_tester.run_batch_comparison(queries, timeout)
        all_results["batch_comparison_tests"] = [
            r.to_dict() for r in batch_results
        ]

        return all_results
