"""AI Learning: Personal knowledge base accumulation and community AI knowledge sharing.

Provides:
- Personal knowledge base: Records successful/failed test cases for future reference
- Automatic experience prompting: AI automatically prompts historical experience in similar scenarios
- Desensitization: Personal knowledge base can be desensitized and optionally uploaded to community
- Community AI knowledge sharing: Community-maintained prompt template library, payload template library, and fix suggestion library
- Knowledge retrieval: AI can reference community-verified payloads and prompts
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class KnowledgeType(Enum):
    """Knowledge entry types."""
    PROMPT_TEMPLATE = "prompt_template"
    PAYLOAD_TEMPLATE = "payload_template"
    EXPLOITATION_CASE = "exploitation_case"
    FIX_SUGGESTION = "fix_suggestion"
    VULNERABILITY_PATTERN = "vulnerability_pattern"
    WAF_BYPASS = "waf_bypass"
    RECONNAISSANCE_TECHNIQUE = "reconnaissance_technique"


class KnowledgeSource(Enum):
    """Knowledge entry sources."""
    PERSONAL = "personal"
    COMMUNITY = "community"
    OFFICIAL = "official"


class KnowledgeStatus(Enum):
    """Knowledge entry status."""
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    PENDING_REVIEW = "pending_review"
    REJECTED = "rejected"


class SharingLevel(Enum):
    """Knowledge sharing levels."""
    PRIVATE = "private"
    ANONYMIZED = "anonymized"
    PUBLIC = "public"


@dataclass
class KnowledgeEntry:
    """Single knowledge base entry.

    Attributes:
        entry_id: Unique entry identifier
        title: Entry title
        description: Entry description
        knowledge_type: Type of knowledge
        source: Knowledge source
        status: Entry status
        sharing_level: Sharing level
        content: Entry content
        tags: Entry tags
        metadata: Additional metadata
        success_count: Number of successful uses
        failure_count: Number of failed uses
        created_at: Entry creation time
        updated_at: Last update time
        created_by: Creator identifier
    """
    entry_id: str = ""
    title: str = ""
    description: str = ""
    knowledge_type: KnowledgeType = KnowledgeType.PROMPT_TEMPLATE
    source: KnowledgeSource = KnowledgeSource.PERSONAL
    status: KnowledgeStatus = KnowledgeStatus.ACTIVE
    sharing_level: SharingLevel = SharingLevel.PRIVATE
    content: str = ""
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    success_count: int = 0
    failure_count: int = 0
    created_at: float = 0.0
    updated_at: float = 0.0
    created_by: str = ""


@dataclass
class TestCase:
    """Penetration test case record.

    Attributes:
        case_id: Unique case identifier
        target: Target identifier
        vulnerability_type: Type of vulnerability tested
        approach: Testing approach used
        payload: Payload used (if applicable)
        result: Test result
        success: Whether test was successful
        lessons_learned: Lessons learned from the case
        tags: Case tags
        created_at: Case creation time
    """
    case_id: str = ""
    target: str = ""
    vulnerability_type: str = ""
    approach: str = ""
    payload: str = ""
    result: str = ""
    success: bool = False
    lessons_learned: str = ""
    tags: List[str] = field(default_factory=list)
    created_at: float = 0.0


@dataclass
class CommunityKnowledge:
    """Community knowledge base information.

    Attributes:
        total_entries: Total number of community entries
        categories: Knowledge categories with counts
        top_contributors: Top knowledge contributors
        recent_entries: Recently added entries
        popular_tags: Most popular tags
    """
    total_entries: int = 0
    categories: Dict[str, int] = field(default_factory=dict)
    top_contributors: List[str] = field(default_factory=list)
    recent_entries: List[KnowledgeEntry] = field(default_factory=list)
    popular_tags: List[str] = field(default_factory=list)


class PersonalKnowledgeBase:
    """Personal knowledge base for penetration testing experience.

    Stores successful and failed test cases, automatically builds
    personal knowledge library for future reference.
    """

    def __init__(self, storage_path: str = "") -> None:
        """Initialize personal knowledge base.

        Args:
            storage_path: Directory path for knowledge persistence.
        """
        self.storage_path = storage_path
        self._entries: Dict[str, KnowledgeEntry] = {}
        self._test_cases: List[TestCase] = []
        self._index: Dict[str, List[str]] = {}

        if storage_path:
            os.makedirs(storage_path, exist_ok=True)
            self._load_from_disk()

    def add_test_case(self, case: TestCase) -> str:
        """Add test case to knowledge base.

        Args:
            case: TestCase to add.

        Returns:
            Case ID.
        """
        if not case.case_id:
            case.case_id = f"case_{int(time.time())}_{hash(case.target) % 10000}"

        case.created_at = time.time()
        self._test_cases.append(case)

        entry = self._create_entry_from_case(case)
        self._entries[entry.entry_id] = entry

        self._update_index(entry)
        self._save_to_disk()

        return case.case_id

    def add_knowledge_entry(self, entry: KnowledgeEntry) -> str:
        """Add knowledge entry to knowledge base.

        Args:
            entry: KnowledgeEntry to add.

        Returns:
            Entry ID.
        """
        if not entry.entry_id:
            entry.entry_id = f"knowledge_{int(time.time())}_{hash(entry.title) % 10000}"

        entry.created_at = time.time()
        entry.updated_at = time.time()
        self._entries[entry.entry_id] = entry

        self._update_index(entry)
        self._save_to_disk()

        return entry.entry_id

    def search_entries(
        self,
        query: str,
        knowledge_type: Optional[KnowledgeType] = None,
        tags: Optional[List[str]] = None,
        limit: int = 10,
    ) -> List[KnowledgeEntry]:
        """Search knowledge entries.

        Args:
            query: Search query string.
            knowledge_type: Optional type filter.
            tags: Optional tag filter.
            limit: Maximum results to return.

        Returns:
            List of matching KnowledgeEntry objects.
        """
        results: List[KnowledgeEntry] = []
        query_lower = query.lower()

        for entry in self._entries.values():
            if knowledge_type and entry.knowledge_type != knowledge_type:
                continue

            if tags and not any(tag in entry.tags for tag in tags):
                continue

            score = 0.0

            if query_lower in entry.title.lower():
                score += 10.0
            if query_lower in entry.description.lower():
                score += 5.0
            if query_lower in entry.content.lower():
                score += 2.0
            for tag in entry.tags:
                if query_lower in tag.lower():
                    score += 3.0

            if score > 0:
                entry.metadata["search_score"] = score
                results.append(entry)

        results.sort(key=lambda e: e.metadata.get("search_score", 0), reverse=True)

        return results[:limit]

    def find_similar_cases(
        self,
        vulnerability_type: str,
        target_type: str = "",
        limit: int = 5,
    ) -> List[TestCase]:
        """Find similar test cases for reference.

        Args:
            vulnerability_type: Vulnerability type to match.
            target_type: Optional target type filter.
            limit: Maximum results to return.

        Returns:
            List of similar TestCase objects.
        """
        similar: List[TestCase] = []

        for case in self._test_cases:
            if case.vulnerability_type.lower() == vulnerability_type.lower():
                if target_type and target_type.lower() not in case.target.lower():
                    continue
                similar.append(case)

        similar.sort(key=lambda c: c.created_at, reverse=True)

        return similar[:limit]

    def get_statistics(self) -> Dict[str, Any]:
        """Get knowledge base statistics.

        Returns:
            Dictionary with knowledge base statistics.
        """
        total_cases = len(self._test_cases)
        successful_cases = sum(1 for c in self._test_cases if c.success)
        failed_cases = total_cases - successful_cases

        vuln_types: Dict[str, int] = {}
        for case in self._test_cases:
            vuln_types[case.vulnerability_type] = vuln_types.get(case.vulnerability_type, 0) + 1

        return {
            "total_cases": total_cases,
            "successful_cases": successful_cases,
            "failed_cases": failed_cases,
            "success_rate": successful_cases / total_cases if total_cases > 0 else 0.0,
            "total_entries": len(self._entries),
            "vulnerability_types": vuln_types,
        }

    def anonymize_entry(self, entry_id: str) -> Optional[KnowledgeEntry]:
        """Anonymize knowledge entry for community sharing.

        Args:
            entry_id: Entry identifier to anonymize.

        Returns:
            Anonymized KnowledgeEntry or None if not found.
        """
        entry = self._entries.get(entry_id)
        if not entry:
            return None

        anonymized = KnowledgeEntry(
            entry_id=entry.entry_id,
            title=entry.title,
            description=entry.description,
            knowledge_type=entry.knowledge_type,
            source=KnowledgeSource.PERSONAL,
            status=entry.status,
            sharing_level=SharingLevel.ANONYMIZED,
            content=self._anonymize_content(entry.content),
            tags=entry.tags,
            metadata={k: v for k, v in entry.metadata.items() if not self._is_sensitive_key(k)},
            success_count=entry.success_count,
            failure_count=entry.failure_count,
            created_at=entry.created_at,
            updated_at=entry.updated_at,
            created_by="anonymous",
        )

        return anonymized

    def _create_entry_from_case(self, case: TestCase) -> KnowledgeEntry:
        """Create knowledge entry from test case.

        Args:
            case: TestCase to convert.

        Returns:
            Created KnowledgeEntry.
        """
        entry = KnowledgeEntry(
            entry_id=f"entry_{case.case_id}",
            title=f"{case.vulnerability_type} - {case.target}",
            description=f"Test case for {case.vulnerability_type} on {case.target}",
            knowledge_type=KnowledgeType.EXPLOITATION_CASE,
            source=KnowledgeSource.PERSONAL,
            status=KnowledgeStatus.ACTIVE,
            sharing_level=SharingLevel.PRIVATE,
            content=f"Approach: {case.approach}\nPayload: {case.payload}\nResult: {case.result}\nLessons: {case.lessons_learned}",
            tags=case.tags,
            success_count=1 if case.success else 0,
            failure_count=0 if case.success else 1,
            created_at=case.created_at,
            updated_at=case.created_at,
            created_by="user",
        )

        return entry

    def _update_index(self, entry: KnowledgeEntry) -> None:
        """Update search index for entry.

        Args:
            entry: KnowledgeEntry to index.
        """
        for tag in entry.tags:
            tag_lower = tag.lower()
            if tag_lower not in self._index:
                self._index[tag_lower] = []
            if entry.entry_id not in self._index[tag_lower]:
                self._index[tag_lower].append(entry.entry_id)

    def _anonymize_content(self, content: str) -> str:
        """Anonymize sensitive information in content.

        Args:
            content: Content to anonymize.

        Returns:
            Anonymized content string.
        """
        anonymized = content

        ip_pattern = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
        anonymized = re.sub(ip_pattern, "[REDACTED_IP]", anonymized)

        domain_pattern = r"\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+\b"
        anonymized = re.sub(domain_pattern, "[REDACTED_DOMAIN]", anonymized)

        email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
        anonymized = re.sub(email_pattern, "[REDACTED_EMAIL]", anonymized)

        return anonymized

    def _is_sensitive_key(self, key: str) -> bool:
        """Check if metadata key is sensitive.

        Args:
            key: Metadata key to check.

        Returns:
            True if key is sensitive.
        """
        sensitive_keys = ["ip", "domain", "target", "host", "url", "email", "credential", "password", "token"]
        return any(s in key.lower() for s in sensitive_keys)

    def _save_to_disk(self) -> None:
        """Save knowledge base to disk."""
        if not self.storage_path:
            return

        try:
            cases_path = os.path.join(self.storage_path, "test_cases.json")
            with open(cases_path, "w", encoding="utf-8") as f:
                json.dump([
                    {
                        "case_id": c.case_id,
                        "target": c.target,
                        "vulnerability_type": c.vulnerability_type,
                        "approach": c.approach,
                        "payload": c.payload,
                        "result": c.result,
                        "success": c.success,
                        "lessons_learned": c.lessons_learned,
                        "tags": c.tags,
                        "created_at": c.created_at,
                    }
                    for c in self._test_cases
                ], f, ensure_ascii=False, indent=2)

            entries_path = os.path.join(self.storage_path, "entries.json")
            with open(entries_path, "w", encoding="utf-8") as f:
                json.dump([
                    {
                        "entry_id": e.entry_id,
                        "title": e.title,
                        "description": e.description,
                        "knowledge_type": e.knowledge_type.value,
                        "source": e.source.value,
                        "status": e.status.value,
                        "sharing_level": e.sharing_level.value,
                        "content": e.content,
                        "tags": e.tags,
                        "metadata": e.metadata,
                        "success_count": e.success_count,
                        "failure_count": e.failure_count,
                        "created_at": e.created_at,
                        "updated_at": e.updated_at,
                        "created_by": e.created_by,
                    }
                    for e in self._entries.values()
                ], f, ensure_ascii=False, indent=2)

        except Exception as e:
            logger.error(f"Failed to save knowledge base: {e}")

    def _load_from_disk(self) -> None:
        """Load knowledge base from disk."""
        if not self.storage_path:
            return

        try:
            cases_path = os.path.join(self.storage_path, "test_cases.json")
            if os.path.exists(cases_path):
                with open(cases_path, "r", encoding="utf-8") as f:
                    cases_data = json.load(f)
                    for case_data in cases_data:
                        case = TestCase(
                            case_id=case_data.get("case_id", ""),
                            target=case_data.get("target", ""),
                            vulnerability_type=case_data.get("vulnerability_type", ""),
                            approach=case_data.get("approach", ""),
                            payload=case_data.get("payload", ""),
                            result=case_data.get("result", ""),
                            success=case_data.get("success", False),
                            lessons_learned=case_data.get("lessons_learned", ""),
                            tags=case_data.get("tags", []),
                            created_at=case_data.get("created_at", 0.0),
                        )
                        self._test_cases.append(case)

            entries_path = os.path.join(self.storage_path, "entries.json")
            if os.path.exists(entries_path):
                with open(entries_path, "r", encoding="utf-8") as f:
                    entries_data = json.load(f)
                    for entry_data in entries_data:
                        entry = KnowledgeEntry(
                            entry_id=entry_data.get("entry_id", ""),
                            title=entry_data.get("title", ""),
                            description=entry_data.get("description", ""),
                            knowledge_type=KnowledgeType(entry_data.get("knowledge_type", "prompt_template")),
                            source=KnowledgeSource(entry_data.get("source", "personal")),
                            status=KnowledgeStatus(entry_data.get("status", "active")),
                            sharing_level=SharingLevel(entry_data.get("sharing_level", "private")),
                            content=entry_data.get("content", ""),
                            tags=entry_data.get("tags", []),
                            metadata=entry_data.get("metadata", {}),
                            success_count=entry_data.get("success_count", 0),
                            failure_count=entry_data.get("failure_count", 0),
                            created_at=entry_data.get("created_at", 0.0),
                            updated_at=entry_data.get("updated_at", 0.0),
                            created_by=entry_data.get("created_by", ""),
                        )
                        self._entries[entry.entry_id] = entry
                        self._update_index(entry)

        except Exception as e:
            logger.error(f"Failed to load knowledge base: {e}")


class CommunityKnowledgeShare:
    """Community AI knowledge sharing system.

    Provides access to community-maintained prompt templates, payload templates,
    and fix suggestion libraries.
    """

    def __init__(self, api_base: str = "https://community.kunlun-pentest.ai/api") -> None:
        """Initialize community knowledge share.

        Args:
            api_base: Community API base URL.
        """
        self.api_base = api_base
        self._local_cache: Dict[str, KnowledgeEntry] = {}
        self._synced_at: float = 0.0

    async def sync_community_knowledge(self) -> CommunityKnowledge:
        """Sync knowledge from community server.

        Returns:
            CommunityKnowledge with synced information.
        """
        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.api_base}/knowledge/sync",
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_community_response(data)

        except ImportError:
            logger.warning("aiohttp not installed. Community sync disabled.")
        except Exception as e:
            logger.error(f"Community sync failed: {e}")

        return CommunityKnowledge()

    async def search_community_knowledge(
        self,
        query: str,
        knowledge_type: Optional[KnowledgeType] = None,
        limit: int = 10,
    ) -> List[KnowledgeEntry]:
        """Search community knowledge base.

        Args:
            query: Search query string.
            knowledge_type: Optional type filter.
            limit: Maximum results to return.

        Returns:
            List of matching KnowledgeEntry objects.
        """
        cache_key = f"{query}_{knowledge_type.value if knowledge_type else 'all'}_{limit}"
        if cache_key in self._local_cache:
            return [self._local_cache[cache_key]]

        try:
            import aiohttp

            params = {"q": query, "limit": limit}
            if knowledge_type:
                params["type"] = knowledge_type.value

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.api_base}/knowledge/search",
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        entries = []
                        for entry_data in data.get("entries", []):
                            entry = self._parse_entry_data(entry_data)
                            entries.append(entry)
                            self._local_cache[f"community_{entry.entry_id}"] = entry
                        return entries

        except ImportError:
            logger.warning("aiohttp not installed. Community search disabled.")
        except Exception as e:
            logger.error(f"Community search failed: {e}")

        return []

    async def upload_to_community(
        self,
        entry: KnowledgeEntry,
        anonymize: bool = True,
    ) -> bool:
        """Upload knowledge entry to community.

        Args:
            entry: KnowledgeEntry to upload.
            anonymize: Whether to anonymize before upload.

        Returns:
            True if upload successful.
        """
        if anonymize:
            entry.sharing_level = SharingLevel.ANONYMIZED
            entry.content = self._anonymize_content(entry.content)
            entry.created_by = "anonymous"

        try:
            import aiohttp

            entry_data = {
                "entry_id": entry.entry_id,
                "title": entry.title,
                "description": entry.description,
                "knowledge_type": entry.knowledge_type.value,
                "content": entry.content,
                "tags": entry.tags,
                "sharing_level": entry.sharing_level.value,
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.api_base}/knowledge/upload",
                    json=entry_data,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as response:
                    return response.status == 200

        except ImportError:
            logger.warning("aiohttp not installed. Community upload disabled.")
            return False
        except Exception as e:
            logger.error(f"Community upload failed: {e}")
            return False

    def get_local_entries(
        self,
        knowledge_type: Optional[KnowledgeType] = None,
        limit: int = 20,
    ) -> List[KnowledgeEntry]:
        """Get locally cached community entries.

        Args:
            knowledge_type: Optional type filter.
            limit: Maximum results to return.

        Returns:
            List of cached KnowledgeEntry objects.
        """
        entries = []
        for key, entry in self._local_cache.items():
            if not key.startswith("community_"):
                continue
            if knowledge_type and entry.knowledge_type != knowledge_type:
                continue
            entries.append(entry)

        entries.sort(key=lambda e: e.success_count, reverse=True)

        return entries[:limit]

    def _parse_community_response(self, data: Dict[str, Any]) -> CommunityKnowledge:
        """Parse community sync response.

        Args:
            data: Response data dictionary.

        Returns:
            Parsed CommunityKnowledge.
        """
        community = CommunityKnowledge(
            total_entries=data.get("total_entries", 0),
            categories=data.get("categories", {}),
            top_contributors=data.get("top_contributors", []),
            popular_tags=data.get("popular_tags", []),
        )

        for entry_data in data.get("recent_entries", []):
            entry = self._parse_entry_data(entry_data)
            community.recent_entries.append(entry)
            self._local_cache[f"community_{entry.entry_id}"] = entry

        self._synced_at = time.time()

        return community

    def _parse_entry_data(self, entry_data: Dict[str, Any]) -> KnowledgeEntry:
        """Parse entry data dictionary.

        Args:
            entry_data: Entry data dictionary.

        Returns:
            Parsed KnowledgeEntry.
        """
        return KnowledgeEntry(
            entry_id=entry_data.get("entry_id", ""),
            title=entry_data.get("title", ""),
            description=entry_data.get("description", ""),
            knowledge_type=KnowledgeType(entry_data.get("knowledge_type", "prompt_template")),
            source=KnowledgeSource.COMMUNITY,
            status=KnowledgeStatus(entry_data.get("status", "active")),
            sharing_level=SharingLevel(entry_data.get("sharing_level", "public")),
            content=entry_data.get("content", ""),
            tags=entry_data.get("tags", []),
            metadata=entry_data.get("metadata", {}),
            success_count=entry_data.get("success_count", 0),
            failure_count=entry_data.get("failure_count", 0),
            created_at=entry_data.get("created_at", 0.0),
            updated_at=entry_data.get("updated_at", 0.0),
            created_by=entry_data.get("created_by", ""),
        )

    def _anonymize_content(self, content: str) -> str:
        """Anonymize sensitive information in content.

        Args:
            content: Content to anonymize.

        Returns:
            Anonymized content string.
        """
        anonymized = content

        ip_pattern = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
        anonymized = re.sub(ip_pattern, "[REDACTED_IP]", anonymized)

        domain_pattern = r"\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+\b"
        anonymized = re.sub(domain_pattern, "[REDACTED_DOMAIN]", anonymized)

        email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
        anonymized = re.sub(email_pattern, "[REDACTED_EMAIL]", anonymized)

        return anonymized


class AILearningSystem:
    """AI learning system for penetration testing experience accumulation.

    Combines personal knowledge base with community knowledge sharing
    to provide intelligent experience-based recommendations.

    Attributes:
        personal_kb: Personal knowledge base instance
        community_share: Community knowledge share instance
        _learning_callback: Optional learning progress callback
    """

    def __init__(
        self,
        storage_path: str = "",
        community_api_base: str = "https://community.kunlun-pentest.ai/api",
        learning_callback: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None,
    ) -> None:
        """Initialize AI learning system.

        Args:
            storage_path: Directory path for personal knowledge persistence.
            community_api_base: Community API base URL.
            learning_callback: Optional async callback for learning progress.
        """
        self.personal_kb = PersonalKnowledgeBase(storage_path)
        self.community_share = CommunityKnowledgeShare(community_api_base)
        self._learning_callback = learning_callback

    async def record_test_case(
        self,
        target: str,
        vulnerability_type: str,
        approach: str,
        payload: str,
        result: str,
        success: bool,
        lessons_learned: str = "",
        tags: Optional[List[str]] = None,
    ) -> str:
        """Record penetration test case.

        Args:
            target: Target identifier.
            vulnerability_type: Type of vulnerability tested.
            approach: Testing approach used.
            payload: Payload used.
            result: Test result.
            success: Whether test was successful.
            lessons_learned: Lessons learned.
            tags: Optional case tags.

        Returns:
            Case ID.
        """
        case = TestCase(
            target=target,
            vulnerability_type=vulnerability_type,
            approach=approach,
            payload=payload,
            result=result,
            success=success,
            lessons_learned=lessons_learned,
            tags=tags or [],
        )

        case_id = self.personal_kb.add_test_case(case)

        if self._learning_callback:
            await self._learning_callback(f"Recorded test case: {vulnerability_type} on {target}", 100.0)

        return case_id

    async def get_recommendations(
        self,
        vulnerability_type: str,
        target_type: str = "",
        include_community: bool = True,
        limit: int = 5,
    ) -> List[Dict[str, Any]]:
        """Get AI recommendations based on historical experience.

        Args:
            vulnerability_type: Vulnerability type to get recommendations for.
            target_type: Optional target type filter.
            include_community: Whether to include community knowledge.
            limit: Maximum recommendations to return.

        Returns:
            List of recommendation dictionaries.
        """
        recommendations: List[Dict[str, Any]] = []

        similar_cases = self.personal_kb.find_similar_cases(vulnerability_type, target_type, limit)
        for case in similar_cases:
            recommendations.append({
                "source": "personal",
                "type": "test_case",
                "case_id": case.case_id,
                "approach": case.approach,
                "payload": case.payload,
                "result": case.result,
                "success": case.success,
                "lessons_learned": case.lessons_learned,
            })

        if include_community:
            community_entries = await self.community_share.search_community_knowledge(
                query=vulnerability_type,
                limit=limit,
            )
            for entry in community_entries:
                recommendations.append({
                    "source": "community",
                    "type": entry.knowledge_type.value,
                    "entry_id": entry.entry_id,
                    "title": entry.title,
                    "content": entry.content,
                    "success_count": entry.success_count,
                    "failure_count": entry.failure_count,
                })

        recommendations.sort(key=lambda r: r.get("success_count", 0) if r.get("success") else 0, reverse=True)

        return recommendations[:limit]

    async def share_to_community(
        self,
        case_id: str,
        anonymize: bool = True,
    ) -> bool:
        """Share test case to community.

        Args:
            case_id: Case ID to share.
            anonymize: Whether to anonymize before sharing.

        Returns:
            True if sharing successful.
        """
        entry_id = f"entry_{case_id}"
        entry = self.personal_kb._entries.get(entry_id)
        if not entry:
            return False

        return await self.community_share.upload_to_community(entry, anonymize)

    def get_learning_statistics(self) -> Dict[str, Any]:
        """Get learning system statistics.

        Returns:
            Dictionary with learning statistics.
        """
        personal_stats = self.personal_kb.get_statistics()

        return {
            "personal": personal_stats,
            "community_cached_entries": len(self.community_share._local_cache),
            "last_community_sync": self.community_share._synced_at,
        }
