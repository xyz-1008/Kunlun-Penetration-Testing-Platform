"""Skill Evaluator: Skill assessment and radar chart generation.

Provides:
- Multi-dimensional skill assessment based on completed tasks, time spent, hints used, and modules utilized
- Personal skill radar chart generation covering: information gathering, vulnerability discovery, exploitation, post-exploitation, reporting
- Assessment reports with community sharing options
- Achievement system with badges and milestones
"""

import asyncio
import json
import logging
import math
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

from .learning_path import (
    LearningPathManager,
    PathDifficulty,
    TaskCategory,
    TaskDefinition,
    TaskProgress,
    TaskStatus,
    UserProgress,
)

logger = logging.getLogger(__name__)


class SkillLevel(Enum):
    """Skill proficiency levels."""
    NOVICE = "novice"
    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    EXPERT = "expert"


class AssessmentType(Enum):
    """Assessment report types."""
    COMPREHENSIVE = "comprehensive"
    QUICK = "quick"
    SKILL_SPECIFIC = "skill_specific"


@dataclass
class SkillDimension:
    """Skill dimension for radar chart.

    Attributes:
        name: Skill dimension name
        score: Current score (0-100)
        level: Skill level
        tasks_completed: Number of tasks completed in this dimension
        total_tasks: Total tasks available in this dimension
        avg_time_per_task: Average time spent per task
        hints_used_ratio: Ratio of hints used vs total hints available
        modules_mastered: List of modules mastered in this dimension
    """
    name: str = ""
    score: float = 0.0
    level: SkillLevel = SkillLevel.NOVICE
    tasks_completed: int = 0
    total_tasks: int = 0
    avg_time_per_task: float = 0.0
    hints_used_ratio: float = 0.0
    modules_mastered: List[str] = field(default_factory=list)


@dataclass
class AssessmentResult:
    """Complete skill assessment result.

    Attributes:
        user_id: User identifier
        assessment_type: Type of assessment
        overall_score: Overall skill score (0-100)
        overall_level: Overall skill level
        dimensions: List of skill dimensions
        strengths: List of strongest skill areas
        weaknesses: List of weakest skill areas
        recommendations: List of improvement recommendations
        achievements: List of earned achievements
        assessment_date: Assessment timestamp
        time_to_complete_seconds: Time taken for assessment
        community_shareable: Whether report can be shared
    """
    user_id: str = ""
    assessment_type: AssessmentType = AssessmentType.COMPREHENSIVE
    overall_score: float = 0.0
    overall_level: SkillLevel = SkillLevel.NOVICE
    dimensions: List[SkillDimension] = field(default_factory=list)
    strengths: List[str] = field(default_factory=list)
    weaknesses: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    achievements: List[str] = field(default_factory=list)
    assessment_date: float = 0.0
    time_to_complete_seconds: float = 0.0
    community_shareable: bool = False


@dataclass
class Achievement:
    """Achievement badge definition.

    Attributes:
        achievement_id: Unique achievement identifier
        name: Achievement name
        description: Achievement description
        icon: Achievement icon identifier
        points_required: Points required to earn
        category: Achievement category
        is_secret: Whether achievement is hidden until earned
    """
    achievement_id: str = ""
    name: str = ""
    description: str = ""
    icon: str = ""
    points_required: int = 0
    category: str = ""
    is_secret: bool = False


class SkillEvaluator:
    """Skill evaluator and radar chart generator.

    Evaluates user skills across multiple dimensions based on
    task completion data and generates radar chart visualizations.
    """

    SKILL_DIMENSIONS = [
        "information_gathering",
        "vulnerability_discovery",
        "exploitation",
        "post_exploitation",
        "reporting",
    ]

    ACHIEVEMENTS = [
        Achievement(
            achievement_id="first_task",
            name="First Steps",
            description="Complete your first task",
            icon="🎯",
            points_required=0,
            category="milestone",
            is_secret=False,
        ),
        Achievement(
            achievement_id="five_tasks",
            name="Getting Started",
            description="Complete 5 tasks",
            icon="🚀",
            points_required=0,
            category="milestone",
            is_secret=False,
        ),
        Achievement(
            achievement_id="ten_tasks",
            name="Dedicated Learner",
            description="Complete 10 tasks",
            icon="📚",
            points_required=0,
            category="milestone",
            is_secret=False,
        ),
        Achievement(
            achievement_id="points_500",
            name="Rising Star",
            description="Earn 500 points",
            icon="⭐",
            points_required=500,
            category="points",
            is_secret=False,
        ),
        Achievement(
            achievement_id="points_1000",
            name="Penetration Pro",
            description="Earn 1000 points",
            icon="🏆",
            points_required=1000,
            category="points",
            is_secret=False,
        ),
        Achievement(
            achievement_id="no_hints",
            name="Self-Reliant",
            description="Complete a task without using any hints",
            icon="🧠",
            points_required=0,
            category="skill",
            is_secret=True,
        ),
        Achievement(
            achievement_id="speed_demon",
            name="Speed Demon",
            description="Complete a task in under half the estimated time",
            icon="⚡",
            points_required=0,
            category="skill",
            is_secret=True,
        ),
        Achievement(
            achievement_id="all_modules",
            name="Tool Master",
            description="Use all Kunlun modules in a single task",
            icon="🛠️",
            points_required=0,
            category="skill",
            is_secret=True,
        ),
        Achievement(
            achievement_id="beginner_complete",
            name="Beginner Graduate",
            description="Complete all beginner path tasks",
            icon="🎓",
            points_required=0,
            category="path",
            is_secret=False,
        ),
        Achievement(
            achievement_id="intermediate_complete",
            name="Intermediate Graduate",
            description="Complete all intermediate path tasks",
            icon="🎓",
            points_required=0,
            category="path",
            is_secret=False,
        ),
        Achievement(
            achievement_id="advanced_complete",
            name="Advanced Graduate",
            description="Complete all advanced path tasks",
            icon="🎓",
            points_required=0,
            category="path",
            is_secret=False,
        ),
    ]

    def __init__(
        self,
        learning_path_manager: Optional[LearningPathManager] = None,
        storage_path: str = "",
    ) -> None:
        """Initialize skill evaluator.

        Args:
            learning_path_manager: Learning path manager instance.
            storage_path: Directory path for assessment storage.
        """
        self.learning_path_manager = learning_path_manager or LearningPathManager()
        self.storage_path = storage_path
        self._assessments: Dict[str, List[AssessmentResult]] = {}

        if storage_path:
            os.makedirs(storage_path, exist_ok=True)
            self._load_assessments()

    async def evaluate_skills(
        self,
        user_id: str,
        assessment_type: AssessmentType = AssessmentType.COMPREHENSIVE,
    ) -> AssessmentResult:
        """Evaluate user skills and generate assessment.

        Args:
            user_id: User identifier.
            assessment_type: Type of assessment to perform.

        Returns:
            AssessmentResult with skill evaluation.
        """
        start_time = time.time()
        user_progress = self.learning_path_manager.get_user_progress(user_id)

        result = AssessmentResult(
            user_id=user_id,
            assessment_type=assessment_type,
            assessment_date=time.time(),
            achievements=user_progress.achievements,
            community_shareable=True,
        )

        result.dimensions = self._calculate_dimensions(user_progress)
        result.overall_score = self._calculate_overall_score(result.dimensions)
        result.overall_level = self._determine_skill_level(result.overall_score)

        result.strengths = self._identify_strengths(result.dimensions)
        result.weaknesses = self._identify_weaknesses(result.dimensions)
        result.recommendations = self._generate_recommendations(result.dimensions, result.weaknesses)

        result.time_to_complete_seconds = time.time() - start_time

        self._store_assessment(user_id, result)
        return result

    async def generate_radar_chart_data(self, user_id: str) -> Dict[str, Any]:
        """Generate radar chart data for visualization.

        Args:
            user_id: User identifier.

        Returns:
            Dictionary with radar chart data points.
        """
        assessment = await self.evaluate_skills(user_id)

        labels = []
        scores = []
        levels = []

        for dim in assessment.dimensions:
            labels.append(dim.name.replace("_", " ").title())
            scores.append(dim.score)
            levels.append(dim.level.value)

        return {
            "labels": labels,
            "scores": scores,
            "levels": levels,
            "overall_score": assessment.overall_score,
            "overall_level": assessment.overall_level.value,
            "chart_type": "radar",
            "max_score": 100,
            "min_score": 0,
        }

    async def generate_assessment_report(
        self,
        user_id: str,
        include_recommendations: bool = True,
        shareable: bool = False,
    ) -> str:
        """Generate human-readable assessment report.

        Args:
            user_id: User identifier.
            include_recommendations: Whether to include recommendations.
            shareable: Whether report is for community sharing.

        Returns:
            Formatted assessment report string.
        """
        assessment = await self.evaluate_skills(user_id)
        assessment.community_shareable = shareable

        lines = [
            "# Kunlun Penetration Testing Skill Assessment Report",
            "",
            f"**User:** {user_id}",
            f"**Assessment Date:** {datetime.fromtimestamp(assessment.assessment_date, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"**Overall Score:** {assessment.overall_score:.1f}/100",
            f"**Skill Level:** {assessment.overall_level.value.title()}",
            "",
            "## Skill Dimensions",
            "",
        ]

        for dim in assessment.dimensions:
            lines.append(f"### {dim.name.replace('_', ' ').title()}")
            lines.append(f"- **Score:** {dim.score:.1f}/100")
            lines.append(f"- **Level:** {dim.level.value.title()}")
            lines.append(f"- **Tasks Completed:** {dim.tasks_completed}/{dim.total_tasks}")
            lines.append(f"- **Average Time per Task:** {dim.avg_time_per_task:.1f} minutes")
            lines.append(f"- **Hints Used Ratio:** {dim.hints_used_ratio:.1%}")
            lines.append("")

        if assessment.strengths:
            lines.append("## Strengths")
            lines.append("")
            for strength in assessment.strengths:
                lines.append(f"- {strength}")
            lines.append("")

        if assessment.weaknesses and include_recommendations:
            lines.append("## Areas for Improvement")
            lines.append("")
            for weakness in assessment.weaknesses:
                lines.append(f"- {weakness}")
            lines.append("")

        if assessment.recommendations and include_recommendations:
            lines.append("## Recommendations")
            lines.append("")
            for rec in assessment.recommendations:
                lines.append(f"- {rec}")
            lines.append("")

        if assessment.achievements:
            lines.append("## Achievements")
            lines.append("")
            for achievement_id in assessment.achievements:
                achievement = self._find_achievement(achievement_id)
                if achievement:
                    lines.append(f"- {achievement.icon} **{achievement.name}**: {achievement.description}")
            lines.append("")

        lines.append("---")
        lines.append("*Generated by Kunlun Penetration Testing Platform*")

        return "\n".join(lines)

    async def get_achievements(self, user_id: str) -> List[Achievement]:
        """Get user's earned achievements.

        Args:
            user_id: User identifier.

        Returns:
            List of earned Achievement objects.
        """
        user_progress = self.learning_path_manager.get_user_progress(user_id)
        earned: List[Achievement] = []

        for achievement_id in user_progress.achievements:
            achievement = self._find_achievement(achievement_id)
            if achievement:
                earned.append(achievement)

        return earned

    async def get_available_achievements(self) -> List[Achievement]:
        """Get all available achievements.

        Returns:
            List of all Achievement objects.
        """
        return [a for a in self.ACHIEVEMENTS if not a.is_secret]

    def _calculate_dimensions(self, user_progress: UserProgress) -> List[SkillDimension]:
        """Calculate skill dimensions from user progress.

        Args:
            user_progress: User progress data.

        Returns:
            List of SkillDimension objects.
        """
        dimensions: List[SkillDimension] = []

        category_mapping = {
            TaskCategory.INFORMATION_GATHERING: "information_gathering",
            TaskCategory.VULNERABILITY_DISCOVERY: "vulnerability_discovery",
            TaskCategory.EXPLOITATION: "exploitation",
            TaskCategory.POST_EXPLOITATION: "post_exploitation",
            TaskCategory.REPORTING: "reporting",
            TaskCategory.LATERAL_MOVEMENT: "post_exploitation",
            TaskCategory.PERSISTENCE: "post_exploitation",
        }

        dimension_tasks: Dict[str, List[Tuple[TaskDefinition, TaskProgress]]] = {
            dim: [] for dim in self.SKILL_DIMENSIONS
        }

        for path in self.learning_path_manager.get_all_paths():
            for task in path.tasks:
                task_progress = user_progress.task_progress.get(task.task_id)
                if task_progress:
                    dim_name = category_mapping.get(task.category, "exploitation")
                    dimension_tasks[dim_name].append((task, task_progress))

        for dim_name in self.SKILL_DIMENSIONS:
            tasks = dimension_tasks[dim_name]
            total_tasks = len([
                t for p in self.learning_path_manager.get_all_paths()
                for t in p.tasks
                if category_mapping.get(t.category) == dim_name
            ])

            if not tasks:
                dimensions.append(SkillDimension(
                    name=dim_name,
                    score=0.0,
                    level=SkillLevel.NOVICE,
                    total_tasks=total_tasks,
                ))
                continue

            completed_tasks = [(t, tp) for t, tp in tasks if tp.status == TaskStatus.COMPLETED]
            tasks_completed = len(completed_tasks)

            if tasks_completed == 0:
                dimensions.append(SkillDimension(
                    name=dim_name,
                    score=0.0,
                    level=SkillLevel.NOVICE,
                    tasks_completed=0,
                    total_tasks=total_tasks,
                ))
                continue

            total_time = sum(tp.time_spent_seconds for _, tp in completed_tasks)
            avg_time_minutes = (total_time / tasks_completed) / 60.0

            total_hints_available = sum(len(t.hints) for t, _ in completed_tasks)
            total_hints_used = sum(len(tp.hints_used) for _, tp in completed_tasks)
            hints_ratio = total_hints_used / total_hints_available if total_hints_available > 0 else 0.0

            base_score = (tasks_completed / total_tasks * 60) if total_tasks > 0 else 0
            efficiency_bonus = max(0, 20 - hints_ratio * 20)
            speed_bonus = 0
            for task, tp in completed_tasks:
                if tp.time_spent_seconds < task.estimated_time_minutes * 30:
                    speed_bonus += 5
            speed_bonus = min(speed_bonus, 20)

            score = min(100, base_score + efficiency_bonus + speed_bonus)

            dimensions.append(SkillDimension(
                name=dim_name,
                score=score,
                level=self._determine_skill_level(score),
                tasks_completed=tasks_completed,
                total_tasks=total_tasks,
                avg_time_per_task=avg_time_minutes,
                hints_used_ratio=hints_ratio,
                modules_mastered=self._get_modules_for_dimension(completed_tasks),
            ))

        return dimensions

    def _calculate_overall_score(self, dimensions: List[SkillDimension]) -> float:
        """Calculate overall skill score.

        Args:
            dimensions: List of skill dimensions.

        Returns:
            Overall score (0-100).
        """
        if not dimensions:
            return 0.0

        weights = {
            "information_gathering": 0.15,
            "vulnerability_discovery": 0.20,
            "exploitation": 0.35,
            "post_exploitation": 0.20,
            "reporting": 0.10,
        }

        total_score = 0.0
        total_weight = 0.0

        for dim in dimensions:
            weight = weights.get(dim.name, 0.1)
            total_score += dim.score * weight
            total_weight += weight

        return total_score / total_weight if total_weight > 0 else 0.0

    def _determine_skill_level(self, score: float) -> SkillLevel:
        """Determine skill level from score.

        Args:
            score: Skill score (0-100).

        Returns:
            SkillLevel enum value.
        """
        if score >= 90:
            return SkillLevel.EXPERT
        elif score >= 75:
            return SkillLevel.ADVANCED
        elif score >= 50:
            return SkillLevel.INTERMEDIATE
        elif score >= 25:
            return SkillLevel.BEGINNER
        else:
            return SkillLevel.NOVICE

    def _identify_strengths(self, dimensions: List[SkillDimension]) -> List[str]:
        """Identify user's strongest skill areas.

        Args:
            dimensions: List of skill dimensions.

        Returns:
            List of strength descriptions.
        """
        sorted_dims = sorted(dimensions, key=lambda d: d.score, reverse=True)
        strengths = []

        for dim in sorted_dims[:2]:
            if dim.score >= 50:
                strengths.append(
                    f"{dim.name.replace('_', ' ').title()}: {dim.score:.1f}/100 ({dim.level.value.title()})"
                )

        return strengths

    def _identify_weaknesses(self, dimensions: List[SkillDimension]) -> List[str]:
        """Identify user's weakest skill areas.

        Args:
            dimensions: List of skill dimensions.

        Returns:
            List of weakness descriptions.
        """
        sorted_dims = sorted(dimensions, key=lambda d: d.score)
        weaknesses = []

        for dim in sorted_dims[:2]:
            if dim.score < 50:
                weaknesses.append(
                    f"{dim.name.replace('_', ' ').title()}: {dim.score:.1f}/100 ({dim.level.value.title()})"
                )

        return weaknesses

    def _generate_recommendations(
        self,
        dimensions: List[SkillDimension],
        weaknesses: List[str],
    ) -> List[str]:
        """Generate improvement recommendations.

        Args:
            dimensions: List of skill dimensions.
            weaknesses: List of identified weaknesses.

        Returns:
            List of recommendation strings.
        """
        recommendations = []

        dim_recommendations = {
            "information_gathering": [
                "Practice more reconnaissance exercises with different target types",
                "Learn to use Kunlun's asset discovery module more effectively",
                "Study OSINT techniques and tools",
            ],
            "vulnerability_discovery": [
                "Complete more vulnerability discovery tasks in the learning paths",
                "Study common vulnerability patterns in web applications",
                "Practice using Kunlun's passive scanner on different targets",
            ],
            "exploitation": [
                "Focus on mastering SQL injection and XSS exploitation techniques",
                "Practice with different exploitation modules in Kunlun",
                "Study real-world exploit techniques from CVE databases",
            ],
            "post_exploitation": [
                "Learn privilege escalation techniques for different operating systems",
                "Practice lateral movement in multi-host environments",
                "Study persistence mechanisms and detection evasion",
            ],
            "reporting": [
                "Practice writing clear and concise vulnerability reports",
                "Learn to use Kunlun's report generation module effectively",
                "Study professional penetration testing report templates",
            ],
        }

        for weakness in weaknesses:
            for dim_name, recs in dim_recommendations.items():
                if dim_name in weakness.lower():
                    recommendations.extend(recs[:2])
                    break

        if not recommendations:
            recommendations.append("Continue practicing with advanced learning path tasks")
            recommendations.append("Try completing tasks without using hints to improve self-reliance")

        return recommendations

    def _get_modules_for_dimension(
        self,
        completed_tasks: List[Tuple[TaskDefinition, TaskProgress]],
    ) -> List[str]:
        """Get modules mastered for a dimension.

        Args:
            completed_tasks: List of completed task tuples.

        Returns:
            List of module names.
        """
        modules: List[str] = []
        for task, tp in completed_tasks:
            for module in task.required_modules:
                if module not in modules:
                    modules.append(module)
        return modules

    def _find_achievement(self, achievement_id: str) -> Optional[Achievement]:
        """Find achievement by ID.

        Args:
            achievement_id: Achievement identifier.

        Returns:
            Achievement or None.
        """
        for achievement in self.ACHIEVEMENTS:
            if achievement.achievement_id == achievement_id:
                return achievement
        return None

    def _store_assessment(self, user_id: str, result: AssessmentResult) -> None:
        """Store assessment result.

        Args:
            user_id: User identifier.
            result: Assessment result.
        """
        if user_id not in self._assessments:
            self._assessments[user_id] = []

        self._assessments[user_id].append(result)

        if self.storage_path:
            self._save_assessments()

    def _load_assessments(self) -> None:
        """Load assessments from storage."""
        if not self.storage_path:
            return

        try:
            assessments_file = os.path.join(self.storage_path, "assessments.json")
            if os.path.exists(assessments_file):
                with open(assessments_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for user_id, assessments in data.items():
                        self._assessments[user_id] = [
                            AssessmentResult(
                                user_id=a.get("user_id", user_id),
                                assessment_type=AssessmentType(a.get("assessment_type", "comprehensive")),
                                overall_score=a.get("overall_score", 0.0),
                                overall_level=SkillLevel(a.get("overall_level", "novice")),
                                achievements=a.get("achievements", []),
                                assessment_date=a.get("assessment_date", time.time()),
                                community_shareable=a.get("community_shareable", False),
                            )
                            for a in assessments
                        ]

        except Exception as e:
            logger.error(f"Failed to load assessments: {e}")

    def _save_assessments(self) -> None:
        """Save assessments to storage."""
        if not self.storage_path:
            return

        try:
            assessments_file = os.path.join(self.storage_path, "assessments.json")
            data = {}

            for user_id, assessments in self._assessments.items():
                data[user_id] = [
                    {
                        "user_id": a.user_id,
                        "assessment_type": a.assessment_type.value,
                        "overall_score": a.overall_score,
                        "overall_level": a.overall_level.value,
                        "achievements": a.achievements,
                        "assessment_date": a.assessment_date,
                        "community_shareable": a.community_shareable,
                    }
                    for a in assessments
                ]

            with open(assessments_file, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)

        except Exception as e:
            logger.error(f"Failed to save assessments: {e}")
