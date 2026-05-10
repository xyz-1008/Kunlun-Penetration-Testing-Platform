"""Template Analytics: Effect analysis dashboard, personalized recommendations, community trends.

Provides:
- Template effect analysis: Detailed dashboard for each template (usage count, success rate, average completion time, user rating trends), A/B testing for different templates on same target, template decay detection (auto-mark "possibly outdated" when success rate continuously drops)
- Personalized recommendation engine: Based on user history ("users who used Shiro exploit also used Fastjson exploit"), based on target environment ("target is Windows Server 2019 domain, recommend domain privilege escalation templates"), based on user skill level (beginners get guided templates, experts get advanced custom templates), trending recommendations
- Community trend analysis: Hottest attack target types and technical directions, adoption curves for emerging vulnerability exploit templates, industry penetration testing focus areas
"""

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class SkillLevel(Enum):
    """User skill levels."""
    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    EXPERT = "expert"


class TrendDirection(Enum):
    """Trend directions."""
    UP = "up"
    DOWN = "down"
    STABLE = "stable"


class DecayStatus(Enum):
    """Template decay status."""
    HEALTHY = "healthy"
    DECLINING = "declining"
    OUTDATED = "outdated"


@dataclass
class TemplateMetrics:
    """Template performance metrics.

    Attributes:
        template_id: Template identifier
        total_executions: Total number of executions
        successful_executions: Number of successful executions
        failed_executions: Number of failed executions
        success_rate: Overall success rate (0-100)
        average_completion_time_ms: Average completion time
        total_downloads: Total downloads
        unique_users: Number of unique users
        average_rating: Average user rating
        rating_count: Number of ratings
        last_used_timestamp: Last usage timestamp
        first_used_timestamp: First usage timestamp
        decay_status: Template decay status
    """
    template_id: str = ""
    total_executions: int = 0
    successful_executions: int = 0
    failed_executions: int = 0
    success_rate: float = 0.0
    average_completion_time_ms: float = 0.0
    total_downloads: int = 0
    unique_users: int = 0
    average_rating: float = 0.0
    rating_count: int = 0
    last_used_timestamp: float = 0.0
    first_used_timestamp: float = 0.0
    decay_status: DecayStatus = DecayStatus.HEALTHY


@dataclass
class ExecutionRecord:
    """Single template execution record.

    Attributes:
        execution_id: Unique execution identifier
        template_id: Template identifier
        user_id: User identifier
        target_environment: Target environment description
        success: Whether execution was successful
        completion_time_ms: Completion time
        timestamp: Execution timestamp
        steps_completed: Number of steps completed
        total_steps: Total steps in template
        error_message: Error message if failed
    """
    execution_id: str = ""
    template_id: str = ""
    user_id: str = ""
    target_environment: str = ""
    success: bool = False
    completion_time_ms: float = 0.0
    timestamp: float = 0.0
    steps_completed: int = 0
    total_steps: int = 0
    error_message: str = ""


@dataclass
class Recommendation:
    """Template recommendation.

    Attributes:
        template_id: Template identifier
        score: Recommendation score (0-100)
        reason: Recommendation reason
        recommendation_type: Type of recommendation
        metadata: Additional metadata
    """
    template_id: str = ""
    score: float = 0.0
    reason: str = ""
    recommendation_type: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TrendData:
    """Community trend data.

    Attributes:
        category: Trend category
        items: List of trend items
        direction: Trend direction
        period: Time period
        data_points: Historical data points
    """
    category: str = ""
    items: List[Dict[str, Any]] = field(default_factory=list)
    direction: TrendDirection = TrendDirection.STABLE
    period: str = "week"
    data_points: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class ABTestResult:
    """A/B test result.

    Attributes:
        test_id: Unique test identifier
        template_a_id: Template A identifier
        template_b_id: Template B identifier
        target_environment: Target environment
        executions_a: Number of executions for template A
        executions_b: Number of executions for template B
        success_rate_a: Success rate for template A
        success_rate_b: Success rate for template B
        avg_time_a: Average time for template A
        avg_time_b: Average time for template B
        winner: Winning template
        confidence: Statistical confidence
    """
    test_id: str = ""
    template_a_id: str = ""
    template_b_id: str = ""
    target_environment: str = ""
    executions_a: int = 0
    executions_b: int = 0
    success_rate_a: float = 0.0
    success_rate_b: float = 0.0
    avg_time_a: float = 0.0
    avg_time_b: float = 0.0
    winner: str = ""
    confidence: float = 0.0


class TemplateAnalytics:
    """Analytics and recommendation engine for template marketplace.

    Provides template effect analysis dashboards, personalized
    recommendations, and community trend analysis.
    """

    DECAY_THRESHOLD = 0.15
    OUTDATED_THRESHOLD = 0.30
    MIN_EXECUTIONS_FOR_DECAY = 10

    def __init__(self, storage_path: str = "") -> None:
        """Initialize template analytics.

        Args:
            storage_path: Directory path for storage.
        """
        self.storage_path = storage_path
        self._metrics: Dict[str, TemplateMetrics] = {}
        self._execution_records: Dict[str, List[ExecutionRecord]] = {}
        self._user_history: Dict[str, List[str]] = {}
        self._ab_tests: Dict[str, ABTestResult] = {}
        self._trends: Dict[str, TrendData] = {}
        self._template_tags: Dict[str, List[str]] = {}
        self._template_environments: Dict[str, List[str]] = {}
        self._template_difficulty: Dict[str, str] = {}

        if storage_path:
            os.makedirs(storage_path, exist_ok=True)
            self._load_data()

    async def record_execution(self, record: ExecutionRecord) -> None:
        """Record template execution.

        Args:
            record: Execution record.
        """
        if record.template_id not in self._execution_records:
            self._execution_records[record.template_id] = []

        self._execution_records[record.template_id].append(record)

        if record.user_id not in self._user_history:
            self._user_history[record.user_id] = []

        if record.template_id not in self._user_history[record.user_id]:
            self._user_history[record.user_id].append(record.template_id)

        self._update_metrics(record)
        self._check_decay(record.template_id)
        self._save_data()

    async def record_download(self, template_id: str, user_id: str) -> None:
        """Record template download.

        Args:
            template_id: Template identifier.
            user_id: User identifier.
        """
        metrics = self._metrics.get(template_id)
        if not metrics:
            metrics = TemplateMetrics(template_id=template_id)
            self._metrics[template_id] = metrics

        metrics.total_downloads += 1
        self._save_data()

    async def record_rating(self, template_id: str, rating: float) -> None:
        """Record template rating.

        Args:
            template_id: Template identifier.
            rating: Rating value (1-5).
        """
        metrics = self._metrics.get(template_id)
        if not metrics:
            metrics = TemplateMetrics(template_id=template_id)
            self._metrics[template_id] = metrics

        total_rating = metrics.average_rating * metrics.rating_count
        metrics.rating_count += 1
        metrics.average_rating = (total_rating + rating) / metrics.rating_count

        self._save_data()

    async def get_template_metrics(self, template_id: str) -> Optional[TemplateMetrics]:
        """Get template metrics.

        Args:
            template_id: Template identifier.

        Returns:
            TemplateMetrics or None.
        """
        return self._metrics.get(template_id)

    async def get_template_dashboard(self, template_id: str) -> Dict[str, Any]:
        """Get detailed dashboard for template.

        Args:
            template_id: Template identifier.

        Returns:
            Dashboard data dict.
        """
        metrics = self._metrics.get(template_id)
        if not metrics:
            return {}

        records = self._execution_records.get(template_id, [])

        recent_records = [
            r for r in records
            if r.timestamp > time.time() - (7 * 86400)
        ]

        weekly_success_rate = 0.0
        if recent_records:
            weekly_success = sum(1 for r in recent_records if r.success)
            weekly_success_rate = (weekly_success / len(recent_records)) * 100

        environment_stats: Dict[str, Dict[str, int]] = {}
        for record in records:
            env = record.target_environment or "unknown"
            if env not in environment_stats:
                environment_stats[env] = {"total": 0, "success": 0}
            environment_stats[env]["total"] += 1
            if record.success:
                environment_stats[env]["success"] += 1

        return {
            "template_id": template_id,
            "total_executions": metrics.total_executions,
            "success_rate": metrics.success_rate,
            "weekly_success_rate": weekly_success_rate,
            "average_completion_time_ms": metrics.average_completion_time_ms,
            "total_downloads": metrics.total_downloads,
            "unique_users": metrics.unique_users,
            "average_rating": metrics.average_rating,
            "rating_count": metrics.rating_count,
            "decay_status": metrics.decay_status.value,
            "environment_stats": environment_stats,
            "execution_trend": self._get_execution_trend(records),
        }

    async def get_personalized_recommendations(
        self,
        user_id: str,
        target_environment: str = "",
        skill_level: SkillLevel = SkillLevel.INTERMEDIATE,
        limit: int = 10,
    ) -> List[Recommendation]:
        """Get personalized template recommendations.

        Args:
            user_id: User identifier.
            target_environment: Target environment.
            skill_level: User skill level.
            limit: Maximum recommendations.

        Returns:
            List of Recommendation objects.
        """
        recommendations: List[Recommendation] = []

        history_based = self._get_history_based_recommendations(user_id, limit)
        recommendations.extend(history_based)

        if target_environment:
            env_based = self._get_environment_based_recommendations(
                target_environment,
                limit,
            )
            recommendations.extend(env_based)

        skill_based = self._get_skill_based_recommendations(skill_level, limit)
        recommendations.extend(skill_based)

        trending = self._get_trending_recommendations(limit)
        recommendations.extend(trending)

        seen: Set[str] = set()
        unique_recommendations: List[Recommendation] = []

        for rec in recommendations:
            if rec.template_id not in seen:
                seen.add(rec.template_id)
                unique_recommendations.append(rec)

        unique_recommendations.sort(key=lambda r: r.score, reverse=True)

        return unique_recommendations[:limit]

    async def start_ab_test(
        self,
        template_a_id: str,
        template_b_id: str,
        target_environment: str,
    ) -> ABTestResult:
        """Start A/B test between two templates.

        Args:
            template_a_id: Template A identifier.
            template_b_id: Template B identifier.
            target_environment: Target environment.

        Returns:
            ABTestResult.
        """
        test_id = f"ab_{template_a_id}_{template_b_id}_{int(time.time())}"

        result = ABTestResult(
            test_id=test_id,
            template_a_id=template_a_id,
            template_b_id=template_b_id,
            target_environment=target_environment,
        )

        self._ab_tests[test_id] = result

        return result

    async def update_ab_test(
        self,
        test_id: str,
        template_id: str,
        success: bool,
        completion_time_ms: float,
    ) -> bool:
        """Update A/B test with execution result.

        Args:
            test_id: Test identifier.
            template_id: Template that was executed.
            success: Whether execution was successful.
            completion_time_ms: Completion time.

        Returns:
            True if updated successfully.
        """
        test = self._ab_tests.get(test_id)
        if not test:
            return False

        if template_id == test.template_a_id:
            test.executions_a += 1
            if success:
                test.success_rate_a = ((test.success_rate_a * (test.executions_a - 1) + 100) / test.executions_a)
            else:
                test.success_rate_a = (test.success_rate_a * (test.executions_a - 1)) / test.executions_a
            test.avg_time_a = ((test.avg_time_a * (test.executions_a - 1) + completion_time_ms) / test.executions_a)
        elif template_id == test.template_b_id:
            test.executions_b += 1
            if success:
                test.success_rate_b = ((test.success_rate_b * (test.executions_b - 1) + 100) / test.executions_b)
            else:
                test.success_rate_b = (test.success_rate_b * (test.executions_b - 1)) / test.executions_b
            test.avg_time_b = ((test.avg_time_b * (test.executions_b - 1) + completion_time_ms) / test.executions_b)

        if test.executions_a >= 5 and test.executions_b >= 5:
            if test.success_rate_a > test.success_rate_b:
                test.winner = test.template_a_id
            elif test.success_rate_b > test.success_rate_a:
                test.winner = test.template_b_id
            else:
                test.winner = "tie"

            test.confidence = min(95.0, (test.executions_a + test.executions_b) * 5)

        return True

    async def get_ab_test_result(self, test_id: str) -> Optional[ABTestResult]:
        """Get A/B test result.

        Args:
            test_id: Test identifier.

        Returns:
            ABTestResult or None.
        """
        return self._ab_tests.get(test_id)

    async def get_community_trends(
        self,
        period: str = "week",
    ) -> Dict[str, TrendData]:
        """Get community trend data.

        Args:
            period: Time period (day/week/month).

        Returns:
            Dict of category to TrendData.
        """
        trends: Dict[str, TrendData] = {}

        template_usage = self._get_template_usage_by_category()
        trends["attack_types"] = TrendData(
            category="attack_types",
            items=template_usage.get("attack_types", []),
            direction=TrendDirection.UP,
            period=period,
        )

        platform_usage = self._get_platform_usage()
        trends["target_platforms"] = TrendData(
            category="target_platforms",
            items=platform_usage,
            direction=TrendDirection.STABLE,
            period=period,
        )

        emerging = self._get_emerging_vulnerabilities()
        trends["emerging_vulnerabilities"] = TrendData(
            category="emerging_vulnerabilities",
            items=emerging,
            direction=TrendDirection.UP,
            period=period,
        )

        industry_focus = self._get_industry_focus()
        trends["industry_focus"] = TrendData(
            category="industry_focus",
            items=industry_focus,
            direction=TrendDirection.STABLE,
            period=period,
        )

        return trends

    async def get_top_templates(
        self,
        metric: str = "downloads",
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        """Get top templates by metric.

        Args:
            metric: Metric to sort by (downloads/success_rate/rating).
            limit: Maximum results.

        Returns:
            List of template data dicts.
        """
        templates: List[Dict[str, Any]] = []

        for tpl_id, metrics in self._metrics.items():
            templates.append({
                "template_id": tpl_id,
                "downloads": metrics.total_downloads,
                "success_rate": metrics.success_rate,
                "average_rating": metrics.average_rating,
                "rating_count": metrics.rating_count,
                "total_executions": metrics.total_executions,
            })

        if metric == "downloads":
            templates.sort(key=lambda t: t["downloads"], reverse=True)
        elif metric == "success_rate":
            templates.sort(key=lambda t: t["success_rate"], reverse=True)
        elif metric == "rating":
            templates.sort(key=lambda t: t["average_rating"], reverse=True)

        return templates[:limit]

    def _update_metrics(self, record: ExecutionRecord) -> None:
        """Update template metrics with execution record.

        Args:
            record: Execution record.
        """
        if record.template_id not in self._metrics:
            self._metrics[record.template_id] = TemplateMetrics(
                template_id=record.template_id,
                first_used_timestamp=record.timestamp,
            )

        metrics = self._metrics[record.template_id]

        metrics.total_executions += 1
        if record.success:
            metrics.successful_executions += 1
        else:
            metrics.failed_executions += 1

        metrics.success_rate = (metrics.successful_executions / metrics.total_executions) * 100

        total_time = metrics.average_completion_time_ms * (metrics.total_executions - 1)
        metrics.average_completion_time_ms = (total_time + record.completion_time_ms) / metrics.total_executions

        metrics.last_used_timestamp = record.timestamp

        if metrics.first_used_timestamp == 0:
            metrics.first_used_timestamp = record.timestamp

    def _check_decay(self, template_id: str) -> None:
        """Check if template is decaying.

        Args:
            template_id: Template identifier.
        """
        metrics = self._metrics.get(template_id)
        if not metrics:
            return

        if metrics.total_executions < self.MIN_EXECUTIONS_FOR_DECAY:
            return

        records = self._execution_records.get(template_id, [])
        if len(records) < self.MIN_EXECUTIONS_FOR_DECAY:
            return

        recent_records = [
            r for r in records
            if r.timestamp > time.time() - (30 * 86400)
        ]

        older_records = [
            r for r in records
            if r.timestamp <= time.time() - (30 * 86400)
        ]

        if not recent_records or not older_records:
            return

        recent_success = sum(1 for r in recent_records if r.success) / len(recent_records)
        older_success = sum(1 for r in older_records if r.success) / len(older_records)

        decline = older_success - recent_success

        if decline >= self.OUTDATED_THRESHOLD:
            metrics.decay_status = DecayStatus.OUTDATED
        elif decline >= self.DECAY_THRESHOLD:
            metrics.decay_status = DecayStatus.DECLINING
        else:
            metrics.decay_status = DecayStatus.HEALTHY

    def _get_history_based_recommendations(
        self,
        user_id: str,
        limit: int,
    ) -> List[Recommendation]:
        """Get recommendations based on user history.

        Args:
            user_id: User identifier.
            limit: Maximum recommendations.

        Returns:
            List of Recommendation objects.
        """
        history = self._user_history.get(user_id, [])
        if not history:
            return []

        recommendations: List[Recommendation] = []

        co_occurrence: Dict[str, int] = {}

        for other_user, other_history in self._user_history.items():
            if other_user == user_id:
                continue

            overlap = set(history) & set(other_history)
            if overlap:
                for tpl_id in other_history:
                    if tpl_id not in history:
                        co_occurrence[tpl_id] = co_occurrence.get(tpl_id, 0) + 1

        for tpl_id, count in co_occurrence.items():
            metrics = self._metrics.get(tpl_id)
            score: float = count * 20
            if metrics:
                score += metrics.success_rate * 0.3

            recommendations.append(Recommendation(
                template_id=tpl_id,
                score=min(score, 100),
                reason="Users with similar history also used this template",
                recommendation_type="collaborative_filtering",
            ))

        recommendations.sort(key=lambda r: r.score, reverse=True)

        return recommendations[:limit]

    def _get_environment_based_recommendations(
        self,
        target_environment: str,
        limit: int,
    ) -> List[Recommendation]:
        """Get recommendations based on target environment.

        Args:
            target_environment: Target environment.
            limit: Maximum recommendations.

        Returns:
            List of Recommendation objects.
        """
        recommendations: List[Recommendation] = []

        for tpl_id, environments in self._template_environments.items():
            if target_environment.lower() in " ".join(environments).lower():
                metrics = self._metrics.get(tpl_id)
                score: float = 50
                if metrics:
                    score += metrics.success_rate * 0.4

                recommendations.append(Recommendation(
                    template_id=tpl_id,
                    score=min(score, 100),
                    reason=f"Recommended for {target_environment} environment",
                    recommendation_type="environment_match",
                ))

        recommendations.sort(key=lambda r: r.score, reverse=True)

        return recommendations[:limit]

    def _get_skill_based_recommendations(
        self,
        skill_level: SkillLevel,
        limit: int,
    ) -> List[Recommendation]:
        """Get recommendations based on skill level.

        Args:
            skill_level: User skill level.
            limit: Maximum recommendations.

        Returns:
            List of Recommendation objects.
        """
        recommendations: List[Recommendation] = []

        skill_difficulty_map = {
            SkillLevel.BEGINNER: ["beginner", "easy"],
            SkillLevel.INTERMEDIATE: ["beginner", "intermediate"],
            SkillLevel.ADVANCED: ["intermediate", "advanced"],
            SkillLevel.EXPERT: ["advanced", "expert"],
        }

        acceptable_difficulties = skill_difficulty_map.get(skill_level, ["intermediate"])

        for tpl_id, difficulty in self._template_difficulty.items():
            if difficulty in acceptable_difficulties:
                metrics = self._metrics.get(tpl_id)
                score: float = 40
                if metrics:
                    score += metrics.average_rating * 10

                recommendations.append(Recommendation(
                    template_id=tpl_id,
                    score=min(score, 100),
                    reason=f"Suitable for {skill_level.value} skill level",
                    recommendation_type="skill_match",
                ))

        recommendations.sort(key=lambda r: r.score, reverse=True)

        return recommendations[:limit]

    def _get_trending_recommendations(self, limit: int) -> List[Recommendation]:
        """Get trending template recommendations.

        Args:
            limit: Maximum recommendations.

        Returns:
            List of Recommendation objects.
        """
        recommendations: List[Recommendation] = []

        sorted_templates = sorted(
            self._metrics.items(),
            key=lambda x: x[1].total_downloads,
            reverse=True,
        )

        for tpl_id, metrics in sorted_templates[:limit]:
            recommendations.append(Recommendation(
                template_id=tpl_id,
                score=metrics.total_downloads,
                reason="Trending this week",
                recommendation_type="trending",
            ))

        return recommendations

    def _get_execution_trend(self, records: List[ExecutionRecord]) -> List[Dict[str, Any]]:
        """Get execution trend data.

        Args:
            records: Execution records.

        Returns:
            List of trend data points.
        """
        trend: Dict[str, Dict[str, int]] = {}

        for record in records:
            day = time.strftime("%Y-%m-%d", time.localtime(record.timestamp))
            if day not in trend:
                trend[day] = {"executions": 0, "success": 0}
            trend[day]["executions"] += 1
            if record.success:
                trend[day]["success"] += 1

        return [
            {"date": date, **data}
            for date, data in sorted(trend.items())
        ]

    def _get_template_usage_by_category(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get template usage by category.

        Returns:
            Dict of category to usage data.
        """
        categories: Dict[str, List[Dict[str, Any]]] = {}

        for tpl_id, metrics in self._metrics.items():
            tags = self._template_tags.get(tpl_id, [])
            for tag in tags:
                if tag not in categories:
                    categories[tag] = []
                categories[tag].append({
                    "template_id": tpl_id,
                    "executions": metrics.total_executions,
                    "success_rate": metrics.success_rate,
                })

        result: List[Dict[str, Any]] = []
        for tag in categories:
            categories[tag].sort(key=lambda x: int(x["executions"]), reverse=True)
            result.extend(categories[tag])

        return {"attack_types": result}

    def _get_platform_usage(self) -> List[Dict[str, Any]]:
        """Get platform usage statistics.

        Returns:
            List of platform usage data.
        """
        platforms: Dict[str, int] = {}

        for tpl_id, environments in self._template_environments.items():
            for env in environments:
                platforms[env] = platforms.get(env, 0) + 1

        return [
            {"platform": platform, "count": count}
            for platform, count in sorted(platforms.items(), key=lambda x: x[1], reverse=True)
        ]

    def _get_emerging_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Get emerging vulnerability trends.

        Returns:
            List of emerging vulnerability data.
        """
        emerging: List[Dict[str, Any]] = []

        for tpl_id, metrics in self._metrics.items():
            if metrics.total_executions >= 5 and metrics.decay_status == DecayStatus.HEALTHY:
                tags = self._template_tags.get(tpl_id, [])
                for tag in tags:
                    if "cve" in tag.lower() or "vuln" in tag.lower():
                        emerging.append({
                            "template_id": tpl_id,
                            "tag": tag,
                            "recent_executions": metrics.total_executions,
                            "success_rate": metrics.success_rate,
                        })

        return sorted(emerging, key=lambda x: x["recent_executions"], reverse=True)[:10]

    def _get_industry_focus(self) -> List[Dict[str, Any]]:
        """Get industry focus areas.

        Returns:
            List of industry focus data.
        """
        industries: Dict[str, int] = {}

        for tpl_id, metrics in self._metrics.items():
            tags = self._template_tags.get(tpl_id, [])
            for tag in tags:
                if any(ind in tag.lower() for ind in ["finance", "healthcare", "government", "education", "retail"]):
                    industries[tag] = industries.get(tag, 0) + metrics.total_executions

        return [
            {"industry": industry, "focus_score": score}
            for industry, score in sorted(industries.items(), key=lambda x: x[1], reverse=True)
        ]

    def _load_data(self) -> None:
        """Load data from storage."""
        if not self.storage_path:
            return

        try:
            data_file = os.path.join(self.storage_path, "analytics_data.json")
            if os.path.exists(data_file):
                with open(data_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                    for tpl_id, metrics_data in data.get("metrics", {}).items():
                        metrics = TemplateMetrics(
                            template_id=tpl_id,
                            total_executions=metrics_data.get("total_executions", 0),
                            successful_executions=metrics_data.get("successful_executions", 0),
                            failed_executions=metrics_data.get("failed_executions", 0),
                            success_rate=metrics_data.get("success_rate", 0.0),
                            average_completion_time_ms=metrics_data.get("average_completion_time_ms", 0.0),
                            total_downloads=metrics_data.get("total_downloads", 0),
                            unique_users=metrics_data.get("unique_users", 0),
                            average_rating=metrics_data.get("average_rating", 0.0),
                            rating_count=metrics_data.get("rating_count", 0),
                            last_used_timestamp=metrics_data.get("last_used_timestamp", 0.0),
                            first_used_timestamp=metrics_data.get("first_used_timestamp", 0.0),
                            decay_status=DecayStatus(metrics_data.get("decay_status", "healthy")),
                        )
                        self._metrics[metrics.template_id] = metrics

                    for tpl_id, records_data in data.get("execution_records", {}).items():
                        records = []
                        for rec_data in records_data:
                            records.append(ExecutionRecord(
                                execution_id=rec_data.get("execution_id", ""),
                                template_id=rec_data.get("template_id", ""),
                                user_id=rec_data.get("user_id", ""),
                                target_environment=rec_data.get("target_environment", ""),
                                success=rec_data.get("success", False),
                                completion_time_ms=rec_data.get("completion_time_ms", 0.0),
                                timestamp=rec_data.get("timestamp", 0.0),
                                steps_completed=rec_data.get("steps_completed", 0),
                                total_steps=rec_data.get("total_steps", 0),
                                error_message=rec_data.get("error_message", ""),
                            ))
                        self._execution_records[tpl_id] = records

                    self._user_history = data.get("user_history", {})

                    for test_id, test_data in data.get("ab_tests", {}).items():
                        test = ABTestResult(
                            test_id=test_id,
                            template_a_id=test_data.get("template_a_id", ""),
                            template_b_id=test_data.get("template_b_id", ""),
                            target_environment=test_data.get("target_environment", ""),
                            executions_a=test_data.get("executions_a", 0),
                            executions_b=test_data.get("executions_b", 0),
                            success_rate_a=test_data.get("success_rate_a", 0.0),
                            success_rate_b=test_data.get("success_rate_b", 0.0),
                            avg_time_a=test_data.get("avg_time_a", 0.0),
                            avg_time_b=test_data.get("avg_time_b", 0.0),
                            winner=test_data.get("winner", ""),
                            confidence=test_data.get("confidence", 0.0),
                        )
                        self._ab_tests[test.test_id] = test

                    self._template_tags = data.get("template_tags", {})
                    self._template_environments = data.get("template_environments", {})
                    self._template_difficulty = data.get("template_difficulty", {})

        except Exception as e:
            logger.error(f"Failed to load analytics data: {e}")

    def _save_data(self) -> None:
        """Save data to storage."""
        if not self.storage_path:
            return

        try:
            data_file = os.path.join(self.storage_path, "analytics_data.json")

            data = {
                "metrics": {
                    tpl_id: {
                        "total_executions": m.total_executions,
                        "successful_executions": m.successful_executions,
                        "failed_executions": m.failed_executions,
                        "success_rate": m.success_rate,
                        "average_completion_time_ms": m.average_completion_time_ms,
                        "total_downloads": m.total_downloads,
                        "unique_users": m.unique_users,
                        "average_rating": m.average_rating,
                        "rating_count": m.rating_count,
                        "last_used_timestamp": m.last_used_timestamp,
                        "first_used_timestamp": m.first_used_timestamp,
                        "decay_status": m.decay_status.value,
                    }
                    for tpl_id, m in self._metrics.items()
                },
                "execution_records": {
                    tpl_id: [
                        {
                            "execution_id": r.execution_id,
                            "template_id": r.template_id,
                            "user_id": r.user_id,
                            "target_environment": r.target_environment,
                            "success": r.success,
                            "completion_time_ms": r.completion_time_ms,
                            "timestamp": r.timestamp,
                            "steps_completed": r.steps_completed,
                            "total_steps": r.total_steps,
                            "error_message": r.error_message,
                        }
                        for r in records
                    ]
                    for tpl_id, records in self._execution_records.items()
                },
                "user_history": self._user_history,
                "ab_tests": {
                    test_id: {
                        "template_a_id": t.template_a_id,
                        "template_b_id": t.template_b_id,
                        "target_environment": t.target_environment,
                        "executions_a": t.executions_a,
                        "executions_b": t.executions_b,
                        "success_rate_a": t.success_rate_a,
                        "success_rate_b": t.success_rate_b,
                        "avg_time_a": t.avg_time_a,
                        "avg_time_b": t.avg_time_b,
                        "winner": t.winner,
                        "confidence": t.confidence,
                    }
                    for test_id, t in self._ab_tests.items()
                },
                "template_tags": self._template_tags,
                "template_environments": self._template_environments,
                "template_difficulty": self._template_difficulty,
            }

            with open(data_file, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)

        except Exception as e:
            logger.error(f"Failed to save analytics data: {e}")
