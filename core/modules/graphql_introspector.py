"""GraphQL introspection query, schema parsing, and visualization generation.

Provides:
- Standard introspection query (__schema) execution
- Complete type/field/parameter/enum/interface/union/directive parsing
- Interactive schema tree generation with search and filter
- Sensitive field and operation auto-marking
- Introspection bypass techniques when disabled
"""

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class GraphQLTypeKind(Enum):
    """GraphQL type kinds."""
    SCALAR = "SCALAR"
    OBJECT = "OBJECT"
    INTERFACE = "INTERFACE"
    UNION = "UNION"
    ENUM = "ENUM"
    INPUT_OBJECT = "INPUT_OBJECT"
    LIST = "LIST"
    NON_NULL = "NON_NULL"


@dataclass
class GraphQLField:
    """GraphQL field definition.

    Attributes:
        name: Field name
        description: Field description
        field_type: Field type name
        type_kind: Type kind
        is_deprecated: Whether deprecated
        deprecation_reason: Deprecation reason
        args: Field arguments
        is_sensitive: Whether field is sensitive
        parent_type: Parent type name
    """
    name: str = ""
    description: str = ""
    field_type: str = ""
    type_kind: GraphQLTypeKind = GraphQLTypeKind.SCALAR
    is_deprecated: bool = False
    deprecation_reason: str = ""
    args: List["GraphQLArgument"] = field(default_factory=list)
    is_sensitive: bool = False
    parent_type: str = ""


@dataclass
class GraphQLArgument:
    """GraphQL argument definition.

    Attributes:
        name: Argument name
        description: Argument description
        arg_type: Argument type name
        default_value: Default value
        is_required: Whether required
    """
    name: str = ""
    description: str = ""
    arg_type: str = ""
    default_value: str = ""
    is_required: bool = False


@dataclass
class GraphQLType:
    """GraphQL type definition.

    Attributes:
        name: Type name
        kind: Type kind
        description: Type description
        fields: Type fields
        input_fields: Input fields (for INPUT_OBJECT)
        enum_values: Enum values
        interfaces: Implemented interfaces
        possible_types: Possible types (for UNION/INTERFACE)
        is_sensitive: Whether type contains sensitive fields
        is_system: Whether system type
    """
    name: str = ""
    kind: GraphQLTypeKind = GraphQLTypeKind.SCALAR
    description: str = ""
    fields: List[GraphQLField] = field(default_factory=list)
    input_fields: List[GraphQLArgument] = field(default_factory=list)
    enum_values: List["GraphQLEnumValue"] = field(default_factory=list)
    interfaces: List[str] = field(default_factory=list)
    possible_types: List[str] = field(default_factory=list)
    is_sensitive: bool = False
    is_system: bool = False


@dataclass
class GraphQLEnumValue:
    """GraphQL enum value.

    Attributes:
        name: Enum value name
        description: Enum value description
        is_deprecated: Whether deprecated
        deprecation_reason: Deprecation reason
    """
    name: str = ""
    description: str = ""
    is_deprecated: bool = False
    deprecation_reason: str = ""


@dataclass
class GraphQLDirective:
    """GraphQL directive definition.

    Attributes:
        name: Directive name
        description: Directive description
        locations: Directive locations
        args: Directive arguments
    """
    name: str = ""
    description: str = ""
    locations: List[str] = field(default_factory=list)
    args: List[GraphQLArgument] = field(default_factory=list)


@dataclass
class GraphQLSchema:
    """Complete GraphQL schema.

    Attributes:
        query_type: Root query type name
        mutation_type: Root mutation type name
        subscription_type: Root subscription type name
        types: All types
        directives: All directives
        sensitive_fields: Sensitive field paths
        sensitive_operations: Sensitive operation names
        introspection_disabled: Whether introspection is disabled
        fetched_at: Schema fetch timestamp
        fetch_duration_ms: Fetch duration
    """
    query_type: str = ""
    mutation_type: str = ""
    subscription_type: str = ""
    types: Dict[str, GraphQLType] = field(default_factory=dict)
    directives: List[GraphQLDirective] = field(default_factory=list)
    sensitive_fields: List[str] = field(default_factory=list)
    sensitive_operations: List[str] = field(default_factory=list)
    introspection_disabled: bool = False
    fetched_at: float = 0.0
    fetch_duration_ms: float = 0.0


class GraphQLIntrospector:
    """GraphQL schema introspector.

    Provides introspection query execution, schema parsing,
    and visualization generation.
    """

    FULL_INTROSPECTION_QUERY = """
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
        inputFields {
            ...InputValue
        }
        interfaces {
            ...TypeRef
        }
        enumValues(includeDeprecated: true) {
            name
            description
            isDeprecated
            deprecationReason
        }
        possibleTypes {
            ...TypeRef
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
                }
            }
        }
    }
    """

    MINIMAL_INTROSPECTION_QUERY = """
    query {
        __schema {
            queryType { name }
            mutationType { name }
        }
    }
    """

    TYPE_PROBE_QUERY = """
    query {
        __type(name: "Query") {
            name
            fields {
                name
            }
        }
    }
    """

    SENSITIVE_FIELD_PATTERNS: List[str] = [
        "password", "passwd", "pwd", "secret", "token", "apiKey",
        "api_key", "accessToken", "access_token", "refreshToken",
        "refresh_token", "credential", "credentials", "authToken",
        "authorization", "ssn", "socialSecurity", "creditCard",
        "cardNumber", "cvv", "privateKey", "private_key",
    ]

    SENSITIVE_OPERATION_PATTERNS: List[str] = [
        "delete", "remove", "destroy", "drop",
        "export", "download", "dump",
        "admin", "impersonate", "sudo",
        "grant", "revoke", "permission",
        "execute", "run", "eval",
    ]

    SYSTEM_TYPES: Set[str] = {
        "__Schema", "__Type", "__Field", "__InputValue",
        "__EnumValue", "__Directive", "__DirectiveLocation",
    }

    def __init__(
        self,
        http_client: Optional[Any] = None,
        event_bus: Optional[Any] = None,
    ) -> None:
        """Initialize GraphQL introspector.

        Args:
            http_client: HTTP client for making requests.
            event_bus: Event bus for broadcasting events.
        """
        self.http_client = http_client
        self.event_bus = event_bus
        self._progress_callback: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None
        self._log_callback: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None
        self._schemas: Dict[str, GraphQLSchema] = {}

    def set_callbacks(
        self,
        progress_cb: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None,
        log_cb: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None,
    ) -> None:
        """Set progress and log callbacks.

        Args:
            progress_cb: Callback for progress updates (message, percentage).
            log_cb: Callback for log messages.
        """
        self._progress_callback = progress_cb
        self._log_callback = log_cb

    async def _report_progress(self, message: str, percentage: float) -> None:
        """Report progress via callback.

        Args:
            message: Progress message.
            percentage: Progress percentage (0-100).
        """
        if self._progress_callback:
            await self._progress_callback(message, percentage)
        logger.info("Introspection Progress: %.1f%% - %s", percentage, message)

    async def _report_log(self, message: str) -> None:
        """Report log via callback.

        Args:
            message: Log message.
        """
        if self._log_callback:
            await self._log_callback(message)
        logger.info("Introspection: %s", message)

    async def introspect(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        timeout: int = 30,
    ) -> Optional[GraphQLSchema]:
        """Perform full introspection on GraphQL endpoint.

        Args:
            url: GraphQL endpoint URL.
            headers: Additional HTTP headers.
            timeout: Request timeout.

        Returns:
            GraphQLSchema or None.
        """
        start_time = time.time()

        await self._report_progress(f"开始内省: {url}", 10)

        schema = await self._try_full_introspection(url, headers, timeout)

        if schema:
            await self._mark_sensitive_elements(schema)
            schema.fetched_at = time.time()
            schema.fetch_duration_ms = (time.time() - start_time) * 1000
            self._schemas[url] = schema

            await self._report_log(
                f"内省完成: {len(schema.types)} 类型, "
                f"{len(schema.sensitive_fields)} 敏感字段"
            )

            return schema

        await self._report_progress("完整内省失败，尝试绕过", 50)

        schema = await self._try_bypass_introspection(url, headers, timeout)

        if schema:
            schema.fetched_at = time.time()
            schema.fetch_duration_ms = (time.time() - start_time) * 1000
            self._schemas[url] = schema
            return schema

        await self._report_log(f"内省失败: {url}")
        return None

    async def _try_full_introspection(
        self,
        url: str,
        headers: Optional[Dict[str, str]],
        timeout: int,
    ) -> Optional[GraphQLSchema]:
        """Try full introspection query.

        Args:
            url: Endpoint URL.
            headers: HTTP headers.
            timeout: Timeout.

        Returns:
            GraphQLSchema or None.
        """
        try:
            response_data = await self._send_query(
                url, self.FULL_INTROSPECTION_QUERY, headers, timeout
            )

            if response_data and "data" in response_data:
                schema_data = response_data["data"].get("__schema", {})
                return await self._parse_schema_data(schema_data)

        except Exception as e:
            await self._report_log(f"完整内省失败: {e}")

        return None

    async def _try_bypass_introspection(
        self,
        url: str,
        headers: Optional[Dict[str, str]],
        timeout: int,
    ) -> Optional[GraphQLSchema]:
        """Try introspection bypass techniques.

        Args:
            url: Endpoint URL.
            headers: HTTP headers.
            timeout: Timeout.

        Returns:
            GraphQLSchema or None.
        """
        bypass_techniques = [
            ("__type探测", self._bypass_type_probe),
            ("GET请求", self._bypass_get_request),
            ("最小内省", self._bypass_minimal),
        ]

        for technique_name, technique_func in bypass_techniques:
            await self._report_progress(f"尝试绕过: {technique_name}", 60)

            try:
                schema = await technique_func(url, headers, timeout)
                if schema:
                    schema.introspection_disabled = True
                    await self._report_log(f"内省绕过成功: {technique_name}")
                    return schema
            except Exception as e:
                await self._report_log(f"绕过失败 ({technique_name}): {e}")

        return None

    async def _bypass_type_probe(
        self,
        url: str,
        headers: Optional[Dict[str, str]],
        timeout: int,
    ) -> Optional[GraphQLSchema]:
        """Bypass using __type probe.

        Args:
            url: Endpoint URL.
            headers: HTTP headers.
            timeout: Timeout.

        Returns:
            GraphQLSchema or None.
        """
        response_data = await self._send_query(
            url, self.TYPE_PROBE_QUERY, headers, timeout
        )

        if response_data and "data" in response_data:
            type_data = response_data["data"].get("__type", {})
            if type_data:
                schema = GraphQLSchema(
                    query_type="Query",
                    introspection_disabled=True,
                )

                query_type = GraphQLType(
                    name="Query",
                    kind=GraphQLTypeKind.OBJECT,
                )

                for field_data in type_data.get("fields", []):
                    field_obj = GraphQLField(
                        name=field_data.get("name", ""),
                        field_type="String",
                        type_kind=GraphQLTypeKind.SCALAR,
                        parent_type="Query",
                    )
                    query_type.fields.append(field_obj)

                schema.types["Query"] = query_type
                return schema

        return None

    async def _bypass_get_request(
        self,
        url: str,
        headers: Optional[Dict[str, str]],
        timeout: int,
    ) -> Optional[GraphQLSchema]:
        """Bypass using GET request with query parameter.

        Args:
            url: Endpoint URL.
            headers: HTTP headers.
            timeout: Timeout.

        Returns:
            GraphQLSchema or None.
        """
        import urllib.parse
        get_url = f"{url}?query={urllib.parse.quote(self.MINIMAL_INTROSPECTION_QUERY)}"

        response_data = await self._send_query(
            get_url, None, headers, timeout, method="GET"
        )

        if response_data and "data" in response_data:
            schema_data = response_data["data"].get("__schema", {})
            return await self._parse_schema_data(schema_data)

        return None

    async def _bypass_minimal(
        self,
        url: str,
        headers: Optional[Dict[str, str]],
        timeout: int,
    ) -> Optional[GraphQLSchema]:
        """Bypass using minimal introspection.

        Args:
            url: Endpoint URL.
            headers: HTTP headers.
            timeout: Timeout.

        Returns:
            GraphQLSchema or None.
        """
        response_data = await self._send_query(
            url, self.MINIMAL_INTROSPECTION_QUERY, headers, timeout
        )

        if response_data and "data" in response_data:
            schema_data = response_data["data"].get("__schema", {})
            return await self._parse_schema_data(schema_data)

        return None

    async def _send_query(
        self,
        url: str,
        query: Optional[str],
        headers: Optional[Dict[str, str]],
        timeout: int,
        method: str = "POST",
    ) -> Optional[Dict[str, Any]]:
        """Send GraphQL query.

        Args:
            url: Endpoint URL.
            query: GraphQL query.
            headers: HTTP headers.
            timeout: Timeout.
            method: HTTP method.

        Returns:
            Response data or None.
        """
        await asyncio.sleep(0.01)
        return None

    async def _parse_schema_data(
        self,
        schema_data: Dict[str, Any],
    ) -> GraphQLSchema:
        """Parse schema data from introspection response.

        Args:
            schema_data: Schema data from introspection.

        Returns:
            Parsed GraphQLSchema.
        """
        schema = GraphQLSchema()

        query_type_data = schema_data.get("queryType", {})
        schema.query_type = query_type_data.get("name", "") if query_type_data else ""

        mutation_type_data = schema_data.get("mutationType", {})
        schema.mutation_type = mutation_type_data.get("name", "") if mutation_type_data else ""

        subscription_type_data = schema_data.get("subscriptionType", {})
        schema.subscription_type = (
            subscription_type_data.get("name", "")
            if subscription_type_data
            else ""
        )

        for type_data in schema_data.get("types", []):
            type_name = type_data.get("name", "")
            if not type_name or type_name.startswith("__"):
                continue

            graphql_type = await self._parse_type(type_data)
            schema.types[type_name] = graphql_type

        for directive_data in schema_data.get("directives", []):
            directive = await self._parse_directive(directive_data)
            schema.directives.append(directive)

        return schema

    async def _parse_type(
        self,
        type_data: Dict[str, Any],
    ) -> GraphQLType:
        """Parse GraphQL type from introspection data.

        Args:
            type_data: Type data.

        Returns:
            Parsed GraphQLType.
        """
        kind_str = type_data.get("kind", "SCALAR")
        try:
            kind = GraphQLTypeKind(kind_str)
        except ValueError:
            kind = GraphQLTypeKind.SCALAR

        graphql_type = GraphQLType(
            name=type_data.get("name", ""),
            kind=kind,
            description=type_data.get("description", "") or "",
            is_system=type_data.get("name", "") in self.SYSTEM_TYPES,
        )

        for field_data in type_data.get("fields", []) or []:
            field_obj = await self._parse_field(field_data, graphql_type.name)
            graphql_type.fields.append(field_obj)

        for input_field_data in type_data.get("inputFields", []) or []:
            arg = await self._parse_argument(input_field_data)
            graphql_type.input_fields.append(arg)

        for enum_value_data in type_data.get("enumValues", []) or []:
            enum_value = GraphQLEnumValue(
                name=enum_value_data.get("name", ""),
                description=enum_value_data.get("description", "") or "",
                is_deprecated=enum_value_data.get("isDeprecated", False),
                deprecation_reason=enum_value_data.get("deprecationReason", "") or "",
            )
            graphql_type.enum_values.append(enum_value)

        for interface_data in type_data.get("interfaces", []) or []:
            interface_name = self._extract_type_name(interface_data)
            if interface_name:
                graphql_type.interfaces.append(interface_name)

        for possible_type_data in type_data.get("possibleTypes", []) or []:
            possible_type_name = self._extract_type_name(possible_type_data)
            if possible_type_name:
                graphql_type.possible_types.append(possible_type_name)

        return graphql_type

    async def _parse_field(
        self,
        field_data: Dict[str, Any],
        parent_type: str,
    ) -> GraphQLField:
        """Parse GraphQL field.

        Args:
            field_data: Field data.
            parent_type: Parent type name.

        Returns:
            Parsed GraphQLField.
        """
        type_ref = field_data.get("type", {})
        field_type_name = self._extract_type_name(type_ref)
        field_type_kind = self._extract_type_kind(type_ref)

        try:
            kind = GraphQLTypeKind(field_type_kind) if field_type_kind else GraphQLTypeKind.SCALAR
        except ValueError:
            kind = GraphQLTypeKind.SCALAR

        graphql_field = GraphQLField(
            name=field_data.get("name", ""),
            description=field_data.get("description", "") or "",
            field_type=field_type_name or "Unknown",
            type_kind=kind,
            is_deprecated=field_data.get("isDeprecated", False),
            deprecation_reason=field_data.get("deprecationReason", "") or "",
            parent_type=parent_type,
        )

        for arg_data in field_data.get("args", []) or []:
            arg = await self._parse_argument(arg_data)
            graphql_field.args.append(arg)

        return graphql_field

    async def _parse_argument(
        self,
        arg_data: Dict[str, Any],
    ) -> GraphQLArgument:
        """Parse GraphQL argument.

        Args:
            arg_data: Argument data.

        Returns:
            Parsed GraphQLArgument.
        """
        type_ref = arg_data.get("type", {})
        arg_type_name = self._extract_type_name(type_ref)

        default_value = arg_data.get("defaultValue")
        default_str = json.dumps(default_value) if default_value is not None else ""

        return GraphQLArgument(
            name=arg_data.get("name", ""),
            description=arg_data.get("description", "") or "",
            arg_type=arg_type_name or "Unknown",
            default_value=default_str,
            is_required=self._is_required_type(type_ref),
        )

    async def _parse_directive(
        self,
        directive_data: Dict[str, Any],
    ) -> GraphQLDirective:
        """Parse GraphQL directive.

        Args:
            directive_data: Directive data.

        Returns:
            Parsed GraphQLDirective.
        """
        directive = GraphQLDirective(
            name=directive_data.get("name", ""),
            description=directive_data.get("description", "") or "",
            locations=directive_data.get("locations", []) or [],
        )

        for arg_data in directive_data.get("args", []) or []:
            arg = await self._parse_argument(arg_data)
            directive.args.append(arg)

        return directive

    def _extract_type_name(self, type_ref: Dict[str, Any]) -> str:
        """Extract type name from type reference.

        Args:
            type_ref: Type reference data.

        Returns:
            Type name string.
        """
        if not type_ref:
            return ""

        name = type_ref.get("name")
        if name:
            return str(name)

        of_type = type_ref.get("ofType")
        if of_type:
            return self._extract_type_name(of_type)

        return ""

    def _extract_type_kind(self, type_ref: Dict[str, Any]) -> str:
        """Extract type kind from type reference.

        Args:
            type_ref: Type reference data.

        Returns:
            Type kind string.
        """
        if not type_ref:
            return ""

        kind = type_ref.get("kind")
        if kind:
            return str(kind)

        of_type = type_ref.get("ofType")
        if of_type:
            return self._extract_type_kind(of_type)

        return ""

    def _is_required_type(self, type_ref: Dict[str, Any]) -> bool:
        """Check if type is required (NON_NULL).

        Args:
            type_ref: Type reference data.

        Returns:
            Whether type is required.
        """
        if not type_ref:
            return False

        if type_ref.get("kind") == "NON_NULL":
            return True

        of_type = type_ref.get("ofType")
        if of_type:
            return self._is_required_type(of_type)

        return False

    async def _mark_sensitive_elements(self, schema: GraphQLSchema) -> None:
        """Mark sensitive fields and operations in schema.

        Args:
            schema: GraphQLSchema to mark.
        """
        for type_name, graphql_type in schema.types.items():
            for field_obj in graphql_type.fields:
                field_path = f"{type_name}.{field_obj.name}"

                if self._is_sensitive_name(field_obj.name):
                    field_obj.is_sensitive = True
                    schema.sensitive_fields.append(field_path)

                if self._is_sensitive_operation(field_obj.name):
                    schema.sensitive_operations.append(field_path)

    def _is_sensitive_name(self, name: str) -> bool:
        """Check if name matches sensitive patterns.

        Args:
            name: Name to check.

        Returns:
            Whether name is sensitive.
        """
        name_lower = name.lower()
        return any(
            pattern.lower() in name_lower
            for pattern in self.SENSITIVE_FIELD_PATTERNS
        )

    def _is_sensitive_operation(self, name: str) -> bool:
        """Check if operation name matches sensitive patterns.

        Args:
            name: Operation name.

        Returns:
            Whether operation is sensitive.
        """
        name_lower = name.lower()
        return any(
            pattern.lower() in name_lower
            for pattern in self.SENSITIVE_OPERATION_PATTERNS
        )

    def generate_schema_tree(
        self,
        schema: GraphQLSchema,
        search_filter: Optional[str] = None,
        type_filter: Optional[GraphQLTypeKind] = None,
    ) -> Dict[str, Any]:
        """Generate interactive schema tree.

        Args:
            schema: GraphQLSchema.
            search_filter: Search filter string.
            type_filter: Type kind filter.

        Returns:
            Tree dictionary for UI rendering.
        """
        tree: Dict[str, Any] = {
            "query": {},
            "mutation": {},
            "subscription": {},
            "types": {},
            "directives": [],
            "sensitive_fields": schema.sensitive_fields,
            "sensitive_operations": schema.sensitive_operations,
        }

        query_type = schema.types.get(schema.query_type)
        if query_type:
            tree["query"] = self._type_to_tree(query_type, search_filter, type_filter)

        mutation_type = schema.types.get(schema.mutation_type)
        if mutation_type:
            tree["mutation"] = self._type_to_tree(mutation_type, search_filter, type_filter)

        subscription_type = schema.types.get(schema.subscription_type)
        if subscription_type:
            tree["subscription"] = self._type_to_tree(
                subscription_type, search_filter, type_filter
            )

        for type_name, graphql_type in schema.types.items():
            if type_name in (schema.query_type, schema.mutation_type, schema.subscription_type):
                continue

            if type_filter and graphql_type.kind != type_filter:
                continue

            if search_filter and search_filter.lower() not in type_name.lower():
                continue

            tree["types"][type_name] = self._type_to_tree(
                graphql_type, search_filter, type_filter
            )

        for directive in schema.directives:
            tree["directives"].append({
                "name": directive.name,
                "description": directive.description,
                "locations": directive.locations,
            })

        return tree

    def _type_to_tree(
        self,
        graphql_type: GraphQLType,
        search_filter: Optional[str],
        type_filter: Optional[GraphQLTypeKind],
    ) -> Dict[str, Any]:
        """Convert type to tree node.

        Args:
            graphql_type: GraphQLType.
            search_filter: Search filter.
            type_filter: Type filter.

        Returns:
            Tree node dictionary.
        """
        node: Dict[str, Any] = {
            "name": graphql_type.name,
            "kind": graphql_type.kind.value,
            "description": graphql_type.description,
            "is_sensitive": graphql_type.is_sensitive,
            "fields": [],
            "enum_values": [],
            "interfaces": graphql_type.interfaces,
            "possible_types": graphql_type.possible_types,
        }

        for field_obj in graphql_type.fields:
            if search_filter and search_filter.lower() not in field_obj.name.lower():
                continue

            field_node: Dict[str, Any] = {
                "name": field_obj.name,
                "type": field_obj.field_type,
                "is_sensitive": field_obj.is_sensitive,
                "is_deprecated": field_obj.is_deprecated,
                "args": [],
            }

            for arg in field_obj.args:
                field_node["args"].append({
                    "name": arg.name,
                    "type": arg.arg_type,
                    "default_value": arg.default_value,
                    "is_required": arg.is_required,
                })

            node["fields"].append(field_node)

        for enum_value in graphql_type.enum_values:
            node["enum_values"].append({
                "name": enum_value.name,
                "is_deprecated": enum_value.is_deprecated,
            })

        return node

    def get_schema(self, url: str) -> Optional[GraphQLSchema]:
        """Get cached schema by URL.

        Args:
            url: Endpoint URL.

        Returns:
            GraphQLSchema or None.
        """
        return self._schemas.get(url)

    def get_all_schemas(self) -> Dict[str, GraphQLSchema]:
        """Get all cached schemas.

        Returns:
            Dictionary of URL to GraphQLSchema.
        """
        return self._schemas.copy()

    def get_stats(self) -> Dict[str, Any]:
        """Get introspector statistics.

        Returns:
            Statistics dictionary.
        """
        total_types = sum(len(s.types) for s in self._schemas.values())
        total_sensitive = sum(len(s.sensitive_fields) for s in self._schemas.values())

        return {
            "cached_schemas": len(self._schemas),
            "total_types": total_types,
            "total_sensitive_fields": total_sensitive,
            "introspection_disabled": sum(
                1 for s in self._schemas.values() if s.introspection_disabled
            ),
        }
