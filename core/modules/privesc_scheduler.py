"""
Windows/Linux提权辅助套件 - 协同调度与任务编排模块
===================================================
提权任务调度器、工作流引擎、定时任务管理。

核心能力:
    1. 提权任务调度器 - 优先级管理、并发控制、定时检查
    2. 提权工作流引擎 - 全流程编排、条件分支、模板导入导出
    3. 多Beacon协同 - 机器重要性排序、权限级别自动排序

Author: 昆仑安全实验室
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


# =============================================================================
# 枚举与数据模型
# =============================================================================

class TaskPriority(str, Enum):
    """任务优先级"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class TaskStatus(str, Enum):
    """任务状态"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


class WorkflowStepStatus(str, Enum):
    """工作流步骤状态"""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


class MachineImportance(str, Enum):
    """机器重要性"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class PrivescTask:
    """提权任务

    Attributes:
        task_id: 任务ID
        beacon_id: Beacon ID
        hostname: 主机名
        priority: 优先级
        machine_importance: 机器重要性
        task_type: 任务类型
        status: 任务状态
        created_at: 创建时间
        started_at: 开始时间
        completed_at: 完成时间
        result: 结果
        error: 错误信息
        timeout: 超时（秒）
    """
    task_id: str = ""
    beacon_id: str = ""
    hostname: str = ""
    priority: TaskPriority = TaskPriority.MEDIUM
    machine_importance: MachineImportance = MachineImportance.MEDIUM
    task_type: str = "privesc_quick"
    status: TaskStatus = TaskStatus.PENDING
    created_at: str = ""
    started_at: str = ""
    completed_at: str = ""
    result: Dict[str, Any] = field(default_factory=dict)
    error: str = ""
    timeout: int = 300

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "task_id": self.task_id,
            "beacon_id": self.beacon_id,
            "hostname": self.hostname,
            "priority": self.priority.value,
            "machine_importance": self.machine_importance.value,
            "task_type": self.task_type,
            "status": self.status.value,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "result": self.result,
            "error": self.error,
            "timeout": self.timeout,
        }

    @property
    def score(self) -> float:
        """计算任务评分（用于排序）

        Returns:
            评分
        """
        priority_scores = {
            TaskPriority.CRITICAL: 100,
            TaskPriority.HIGH: 75,
            TaskPriority.MEDIUM: 50,
            TaskPriority.LOW: 25,
        }
        importance_scores = {
            MachineImportance.CRITICAL: 100,
            MachineImportance.HIGH: 75,
            MachineImportance.MEDIUM: 50,
            MachineImportance.LOW: 25,
        }

        return (
            priority_scores.get(self.priority, 50) * 0.6
            + importance_scores.get(self.machine_importance, 50) * 0.4
        )


@dataclass
class WorkflowStep:
    """工作流步骤

    Attributes:
        step_id: 步骤ID
        name: 步骤名
        description: 描述
        handler: 处理函数
        condition: 条件函数
        on_success: 成功时跳转的步骤
        on_failure: 失败时跳转的步骤
        timeout: 超时（秒）
        status: 步骤状态
        result: 结果
        error: 错误信息
        started_at: 开始时间
        completed_at: 完成时间
    """
    step_id: str = ""
    name: str = ""
    description: str = ""
    handler: Optional[Callable[..., Coroutine]] = None
    condition: Optional[Callable[..., Coroutine]] = None
    on_success: str = ""
    on_failure: str = ""
    timeout: int = 60
    status: WorkflowStepStatus = WorkflowStepStatus.PENDING
    result: Any = None
    error: str = ""
    started_at: str = ""
    completed_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "step_id": self.step_id,
            "name": self.name,
            "description": self.description,
            "condition": self.condition.__name__ if self.condition else None,
            "on_success": self.on_success,
            "on_failure": self.on_failure,
            "timeout": self.timeout,
            "status": self.status.value,
            "result": str(self.result) if self.result else None,
            "error": self.error,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }


@dataclass
class WorkflowInstance:
    """工作流实例

    Attributes:
        workflow_id: 工作流ID
        template_id: 模板ID
        task_id: 关联任务ID
        beacon_id: Beacon ID
        status: 工作流状态
        current_step: 当前步骤
        steps: 步骤列表
        created_at: 创建时间
        started_at: 开始时间
        completed_at: 完成时间
        result: 结果
    """
    workflow_id: str = ""
    template_id: str = ""
    task_id: str = ""
    beacon_id: str = ""
    status: TaskStatus = TaskStatus.PENDING
    current_step: str = ""
    steps: List[WorkflowStep] = field(default_factory=list)
    created_at: str = ""
    started_at: str = ""
    completed_at: str = ""
    result: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "workflow_id": self.workflow_id,
            "template_id": self.template_id,
            "task_id": self.task_id,
            "beacon_id": self.beacon_id,
            "status": self.status.value,
            "current_step": self.current_step,
            "steps": [s.to_dict() for s in self.steps],
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "result": self.result,
        }


@dataclass
class WorkflowTemplate:
    """工作流模板

    Attributes:
        template_id: 模板ID
        name: 模板名
        description: 描述
        version: 版本
        steps: 步骤定义
        created_at: 创建时间
        updated_at: 更新时间
        author: 作者
    """
    template_id: str = ""
    name: str = ""
    description: str = ""
    version: str = "1.0.0"
    steps: List[Dict[str, Any]] = field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""
    author: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "template_id": self.template_id,
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "steps": self.steps,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "author": self.author,
        }

    def to_json(self) -> str:
        """导出为JSON

        Returns:
            JSON字符串
        """
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)

    @classmethod
    def from_json(cls, json_str: str) -> "WorkflowTemplate":
        """从JSON导入

        Args:
            json_str: JSON字符串

        Returns:
            工作流模板
        """
        data = json.loads(json_str)
        template = cls()
        template.template_id = data.get("template_id", "")
        template.name = data.get("name", "")
        template.description = data.get("description", "")
        template.version = data.get("version", "1.0.0")
        template.steps = data.get("steps", [])
        template.created_at = data.get("created_at", "")
        template.updated_at = data.get("updated_at", "")
        template.author = data.get("author", "")
        return template


# =============================================================================
# 提权任务调度器
# =============================================================================

class PrivescTaskScheduler:
    """提权任务调度器

    统一管理所有提权任务的优先级、并发和排队。

    Attributes:
        _max_concurrent: 最大并发数
        _task_queue: 任务队列
        _running_tasks: 运行中的任务
        _completed_tasks: 已完成的任务
        _handlers: 任务处理器
        _scheduler_task: 调度器任务
    """

    def __init__(self, max_concurrent: int = 5) -> None:
        """初始化提权任务调度器

        Args:
            max_concurrent: 最大并发数
        """
        self._max_concurrent = max_concurrent
        self._task_queue: List[PrivescTask] = []
        self._running_tasks: Dict[str, PrivescTask] = {}
        self._completed_tasks: Dict[str, PrivescTask] = {}
        self._handlers: Dict[str, Callable[..., Coroutine]] = {}
        self._scheduler_task: Optional[asyncio.Task] = None
        self._running = False

    def register_handler(
        self,
        task_type: str,
        handler: Callable[..., Coroutine],
    ) -> None:
        """注册任务处理器

        Args:
            task_type: 任务类型
            handler: 处理函数
        """
        self._handlers[task_type] = handler

    async def submit_task(self, task: PrivescTask) -> str:
        """提交任务

        Args:
            task: 提权任务

        Returns:
            任务ID
        """
        if not task.task_id:
            task.task_id = f"task_{uuid.uuid4().hex[:12]}"
        if not task.created_at:
            task.created_at = datetime.now().isoformat()

        self._task_queue.append(task)
        self._task_queue.sort(key=lambda t: t.score, reverse=True)

        logger.info(f"任务提交: {task.task_id}, 类型: {task.task_type}, 优先级: {task.priority.value}")

        if not self._running:
            await self.start()

        return task.task_id

    async def submit_batch(self, tasks: List[PrivescTask]) -> List[str]:
        """批量提交任务

        Args:
            tasks: 任务列表

        Returns:
            任务ID列表
        """
        ids = []
        for task in tasks:
            tid = await self.submit_task(task)
            ids.append(tid)
        return ids

    async def cancel_task(self, task_id: str) -> bool:
        """取消任务

        Args:
            task_id: 任务ID

        Returns:
            是否成功
        """
        for i, task in enumerate(self._task_queue):
            if task.task_id == task_id:
                task.status = TaskStatus.CANCELLED
                self._task_queue.pop(i)
                logger.info(f"任务取消: {task_id}")
                return True

        if task_id in self._running_tasks:
            task = self._running_tasks[task_id]
            task.status = TaskStatus.CANCELLED
            logger.info(f"运行中任务取消: {task_id}")
            return True

        return False

    async def start(self) -> None:
        """启动调度器"""
        if self._running:
            return

        self._running = True
        self._scheduler_task = asyncio.create_task(self._schedule_loop())
        logger.info("提权任务调度器已启动")

    async def stop(self) -> None:
        """停止调度器"""
        self._running = False
        if self._scheduler_task:
            self._scheduler_task.cancel()
            try:
                await self._scheduler_task
            except asyncio.CancelledError:
                pass
        logger.info("提权任务调度器已停止")

    async def get_task_status(self, task_id: str) -> Optional[PrivescTask]:
        """获取任务状态

        Args:
            task_id: 任务ID

        Returns:
            任务信息
        """
        if task_id in self._running_tasks:
            return self._running_tasks[task_id]
        if task_id in self._completed_tasks:
            return self._completed_tasks[task_id]
        for task in self._task_queue:
            if task.task_id == task_id:
                return task
        return None

    async def get_queue_status(self) -> Dict[str, Any]:
        """获取队列状态

        Returns:
            队列状态
        """
        return {
            "queued": len(self._task_queue),
            "running": len(self._running_tasks),
            "completed": len(self._completed_tasks),
            "max_concurrent": self._max_concurrent,
            "is_running": self._running,
        }

    async def _schedule_loop(self) -> None:
        """调度循环"""
        while self._running:
            await self._process_queue()
            await asyncio.sleep(1)

    async def _process_queue(self) -> None:
        """处理任务队列"""
        while (
            self._task_queue
            and len(self._running_tasks) < self._max_concurrent
        ):
            task = self._task_queue.pop(0)

            if task.status == TaskStatus.CANCELLED:
                continue

            asyncio.create_task(self._execute_task(task))

    async def _execute_task(self, task: PrivescTask) -> None:
        """执行任务

        Args:
            task: 提权任务
        """
        task.status = TaskStatus.RUNNING
        task.started_at = datetime.now().isoformat()
        self._running_tasks[task.task_id] = task

        handler = self._handlers.get(task.task_type)
        if not handler:
            task.status = TaskStatus.FAILED
            task.error = f"未注册处理器: {task.task_type}"
            self._complete_task(task)
            return

        try:
            result = await asyncio.wait_for(
                handler(task),
                timeout=task.timeout,
            )
            task.status = TaskStatus.COMPLETED
            task.result = result if isinstance(result, dict) else {"data": result}
        except asyncio.TimeoutError:
            task.status = TaskStatus.TIMEOUT
            task.error = f"任务超时: {task.timeout}秒"
        except Exception as e:
            task.status = TaskStatus.FAILED
            task.error = str(e)

        task.completed_at = datetime.now().isoformat()
        self._complete_task(task)

    def _complete_task(self, task: PrivescTask) -> None:
        """完成任务

        Args:
            task: 提权任务
        """
        self._running_tasks.pop(task.task_id, None)
        self._completed_tasks[task.task_id] = task

        logger.info(
            f"任务完成: {task.task_id}, 状态: {task.status.value}, "
            f"耗时: {self._calc_duration(task)}秒"
        )

    def _calc_duration(self, task: PrivescTask) -> float:
        """计算任务耗时

        Args:
            task: 提权任务

        Returns:
            耗时（秒）
        """
        if task.started_at and task.completed_at:
            start = datetime.fromisoformat(task.started_at)
            end = datetime.fromisoformat(task.completed_at)
            return (end - start).total_seconds()
        return 0.0


# =============================================================================
# 定时提权检查
# =============================================================================

class ScheduledPrivescChecker:
    """定时提权检查器

    每隔N小时对已控机器自动执行提权检查。

    Attributes:
        _interval: 检查间隔（小时）
        _scheduler: 任务调度器
        _beacon_list: Beacon列表
        _check_task: 检查任务
    """

    def __init__(
        self,
        scheduler: PrivescTaskScheduler,
        interval_hours: int = 4,
    ) -> None:
        """初始化定时提权检查器

        Args:
            scheduler: 任务调度器
            interval_hours: 检查间隔（小时）
        """
        self._scheduler = scheduler
        self._interval = interval_hours
        self._beacon_list: List[Dict[str, Any]] = []
        self._check_task: Optional[asyncio.Task] = None
        self._running = False

    def set_beacons(self, beacons: List[Dict[str, Any]]) -> None:
        """设置Beacon列表

        Args:
            beacons: Beacon列表
        """
        self._beacon_list = beacons

    async def start(self) -> None:
        """启动定时检查"""
        if self._running:
            return

        self._running = True
        self._check_task = asyncio.create_task(self._check_loop())
        logger.info(f"定时提权检查已启动，间隔: {self._interval}小时")

    async def stop(self) -> None:
        """停止定时检查"""
        self._running = False
        if self._check_task:
            self._check_task.cancel()
            try:
                await self._check_task
            except asyncio.CancelledError:
                pass
        logger.info("定时提权检查已停止")

    async def _check_loop(self) -> None:
        """检查循环"""
        while self._running:
            await self._run_checks()
            await asyncio.sleep(self._interval * 3600)

    async def _run_checks(self) -> None:
        """执行检查"""
        tasks = []
        for beacon in self._beacon_list:
            task = PrivescTask(
                beacon_id=beacon.get("id", ""),
                hostname=beacon.get("hostname", ""),
                priority=TaskPriority.MEDIUM,
                machine_importance=MachineImportance(
                    beacon.get("importance", "medium")
                ),
                task_type="privesc_quick",
            )
            tasks.append(task)

        if tasks:
            await self._scheduler.submit_batch(tasks)
            logger.info(f"定时检查: 提交 {len(tasks)} 个任务")


# =============================================================================
# 提权工作流引擎
# =============================================================================

class PrivescWorkflowEngine:
    """提权工作流引擎

    将提权全流程编排为可配置的工作流。

    Attributes:
        _templates: 工作流模板
        _instances: 工作流实例
        _step_handlers: 步骤处理器
    """

    DEFAULT_WORKFLOW_STEPS = [
        {
            "step_id": "collect",
            "name": "信息收集",
            "description": "收集目标系统信息",
            "on_success": "analyze",
            "on_failure": "fallback",
            "timeout": 120,
        },
        {
            "step_id": "analyze",
            "name": "分析评估",
            "description": "分析提权向量",
            "on_success": "decide",
            "on_failure": "fallback",
            "timeout": 60,
        },
        {
            "step_id": "decide",
            "name": "决策",
            "description": "选择最佳利用方式",
            "on_success": "exploit",
            "on_failure": "fallback",
            "timeout": 30,
        },
        {
            "step_id": "exploit",
            "name": "利用",
            "description": "执行提权利用",
            "on_success": "verify",
            "on_failure": "fallback",
            "timeout": 300,
        },
        {
            "step_id": "verify",
            "name": "验证",
            "description": "验证提权结果",
            "on_success": "persist",
            "on_failure": "rollback",
            "timeout": 60,
        },
        {
            "step_id": "persist",
            "name": "持久化",
            "description": "建立持久化访问",
            "on_success": "cleanup",
            "on_failure": "cleanup",
            "timeout": 120,
        },
        {
            "step_id": "cleanup",
            "name": "清理",
            "description": "清理利用痕迹",
            "on_success": "complete",
            "on_failure": "complete",
            "timeout": 60,
        },
        {
            "step_id": "fallback",
            "name": "降级策略",
            "description": "尝试降级利用",
            "on_success": "verify",
            "on_failure": "rollback",
            "timeout": 300,
        },
        {
            "step_id": "rollback",
            "name": "回滚",
            "description": "回滚系统状态",
            "on_success": "complete",
            "on_failure": "complete",
            "timeout": 60,
        },
        {
            "step_id": "complete",
            "name": "完成",
            "description": "工作流完成",
            "on_success": "",
            "on_failure": "",
            "timeout": 10,
        },
    ]

    def __init__(self) -> None:
        """初始化提权工作流引擎"""
        self._templates: Dict[str, WorkflowTemplate] = {}
        self._instances: Dict[str, WorkflowInstance] = {}
        self._step_handlers: Dict[str, Callable[..., Coroutine]] = {}

        self._register_default_template()

    def register_step_handler(
        self,
        step_id: str,
        handler: Callable[..., Coroutine],
    ) -> None:
        """注册步骤处理器

        Args:
            step_id: 步骤ID
            handler: 处理函数
        """
        self._step_handlers[step_id] = handler

    def register_template(self, template: WorkflowTemplate) -> None:
        """注册工作流模板

        Args:
            template: 工作流模板
        """
        self._templates[template.template_id] = template
        logger.info(f"工作流模板注册: {template.name} v{template.version}")

    async def execute_workflow(
        self,
        template_id: str,
        task_id: str,
        beacon_id: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> WorkflowInstance:
        """执行工作流

        Args:
            template_id: 模板ID
            task_id: 任务ID
            beacon_id: Beacon ID
            context: 上下文

        Returns:
            工作流实例
        """
        template = self._templates.get(template_id)
        if not template:
            raise ValueError(f"工作流模板不存在: {template_id}")

        instance = WorkflowInstance(
            workflow_id=f"wf_{uuid.uuid4().hex[:12]}",
            template_id=template_id,
            task_id=task_id,
            beacon_id=beacon_id,
            created_at=datetime.now().isoformat(),
        )

        instance.steps = self._build_steps(template)
        self._instances[instance.workflow_id] = instance

        await self._run_workflow(instance, context or {})

        return instance

    async def get_workflow_status(
        self, workflow_id: str,
    ) -> Optional[WorkflowInstance]:
        """获取工作流状态

        Args:
            workflow_id: 工作流ID

        Returns:
            工作流实例
        """
        return self._instances.get(workflow_id)

    def export_template(self, template_id: str) -> Optional[str]:
        """导出工作流模板

        Args:
            template_id: 模板ID

        Returns:
            JSON字符串
        """
        template = self._templates.get(template_id)
        if template:
            return template.to_json()
        return None

    def import_template(self, json_str: str) -> WorkflowTemplate:
        """导入工作流模板

        Args:
            json_str: JSON字符串

        Returns:
            工作流模板
        """
        template = WorkflowTemplate.from_json(json_str)
        self.register_template(template)
        return template

    def _register_default_template(self) -> None:
        """注册默认工作流模板"""
        template = WorkflowTemplate(
            template_id="default_privesc",
            name="默认提权工作流",
            description="收集→分析→决策→利用→验证→持久化→清理",
            version="1.0.0",
            steps=self.DEFAULT_WORKFLOW_STEPS,
            created_at=datetime.now().isoformat(),
            updated_at=datetime.now().isoformat(),
            author="昆仑安全实验室",
        )
        self._templates["default_privesc"] = template

    def _build_steps(
        self, template: WorkflowTemplate,
    ) -> List[WorkflowStep]:
        """构建步骤列表

        Args:
            template: 工作流模板

        Returns:
            步骤列表
        """
        steps = []
        for step_def in template.steps:
            step = WorkflowStep(
                step_id=step_def.get("step_id", ""),
                name=step_def.get("name", ""),
                description=step_def.get("description", ""),
                on_success=step_def.get("on_success", ""),
                on_failure=step_def.get("on_failure", ""),
                timeout=step_def.get("timeout", 60),
            )
            steps.append(step)
        return steps

    async def _run_workflow(
        self,
        instance: WorkflowInstance,
        context: Dict[str, Any],
    ) -> None:
        """运行工作流

        Args:
            instance: 工作流实例
            context: 上下文
        """
        instance.started_at = datetime.now().isoformat()
        instance.status = TaskStatus.RUNNING

        current_step_id = instance.steps[0].step_id if instance.steps else ""

        while current_step_id:
            step = self._find_step(instance, current_step_id)
            if not step:
                break

            instance.current_step = current_step_id
            step.status = WorkflowStepStatus.RUNNING
            step.started_at = datetime.now().isoformat()

            handler = self._step_handlers.get(current_step_id)

            try:
                if handler:
                    step.result = await asyncio.wait_for(
                        handler(context),
                        timeout=step.timeout,
                    )
                    step.status = WorkflowStepStatus.SUCCESS
                    current_step_id = step.on_success
                else:
                    step.status = WorkflowStepStatus.SKIPPED
                    current_step_id = step.on_success

            except asyncio.TimeoutError:
                step.status = WorkflowStepStatus.FAILED
                step.error = f"步骤超时: {step.timeout}秒"
                current_step_id = step.on_failure

            except Exception as e:
                step.status = WorkflowStepStatus.FAILED
                step.error = str(e)
                current_step_id = step.on_failure

            step.completed_at = datetime.now().isoformat()

            if current_step_id == "complete" or not current_step_id:
                break

        instance.status = TaskStatus.COMPLETED
        instance.completed_at = datetime.now().isoformat()
        instance.result = context

    def _find_step(
        self, instance: WorkflowInstance, step_id: str,
    ) -> Optional[WorkflowStep]:
        """查找步骤

        Args:
            instance: 工作流实例
            step_id: 步骤ID

        Returns:
            步骤
        """
        for step in instance.steps:
            if step.step_id == step_id:
                return step
        return None


# =============================================================================
# 主调度模块
# =============================================================================

class PrivescSchedulerModule:
    """协同调度与任务编排模块

    整合任务调度器、定时检查器、工作流引擎。

    Attributes:
        _scheduler: 任务调度器
        _scheduled_checker: 定时检查器
        _workflow_engine: 工作流引擎
    """

    def __init__(
        self,
        max_concurrent: int = 5,
        check_interval_hours: int = 4,
    ) -> None:
        """初始化调度模块

        Args:
            max_concurrent: 最大并发数
            check_interval_hours: 检查间隔（小时）
        """
        self._scheduler = PrivescTaskScheduler(max_concurrent)
        self._scheduled_checker = ScheduledPrivescChecker(
            self._scheduler, check_interval_hours,
        )
        self._workflow_engine = PrivescWorkflowEngine()

    @property
    def scheduler(self) -> PrivescTaskScheduler:
        """获取任务调度器"""
        return self._scheduler

    @property
    def workflow_engine(self) -> PrivescWorkflowEngine:
        """获取工作流引擎"""
        return self._workflow_engine

    async def submit_task(self, task: PrivescTask) -> str:
        """提交任务

        Args:
            task: 提权任务

        Returns:
            任务ID
        """
        return await self._scheduler.submit_task(task)

    async def submit_workflow(
        self,
        task: PrivescTask,
        template_id: str = "default_privesc",
        context: Optional[Dict[str, Any]] = None,
    ) -> str:
        """提交工作流任务

        Args:
            task: 提权任务
            template_id: 模板ID
            context: 上下文

        Returns:
            任务ID
        """
        task_id = await self._scheduler.submit_task(task)

        async def workflow_handler(t: PrivescTask) -> Dict[str, Any]:
            return await self._workflow_engine.execute_workflow(
                template_id, t.task_id, t.beacon_id, context,
            )

        self._scheduler.register_handler("workflow", workflow_handler)

        workflow_task = PrivescTask(
            task_id=f"wf_{task_id}",
            beacon_id=task.beacon_id,
            hostname=task.hostname,
            priority=task.priority,
            machine_importance=task.machine_importance,
            task_type="workflow",
            timeout=task.timeout * 3,
        )
        await self._scheduler.submit_task(workflow_task)

        return task_id

    async def start_scheduled_checks(
        self, beacons: List[Dict[str, Any]],
    ) -> None:
        """启动定时检查

        Args:
            beacons: Beacon列表
        """
        self._scheduled_checker.set_beacons(beacons)
        await self._scheduled_checker.start()

    async def stop_scheduled_checks(self) -> None:
        """停止定时检查"""
        await self._scheduled_checker.stop()

    async def start(self) -> None:
        """启动调度模块"""
        await self._scheduler.start()

    async def stop(self) -> None:
        """停止调度模块"""
        await self._scheduler.stop()
        await self._scheduled_checker.stop()

    async def get_status(self) -> Dict[str, Any]:
        """获取调度状态

        Returns:
            状态信息
        """
        return {
            "scheduler": await self._scheduler.get_queue_status(),
            "scheduled_checker_running": self._scheduled_checker._running,
            "templates": list(self._workflow_engine._templates.keys()),
            "workflows": len(self._workflow_engine._instances),
        }


# =============================================================================
# 全局单例
# =============================================================================

_scheduler_module: Optional[PrivescSchedulerModule] = None


def get_scheduler_module() -> PrivescSchedulerModule:
    """获取调度模块全局单例

    Returns:
        PrivescSchedulerModule 实例
    """
    global _scheduler_module
    if _scheduler_module is None:
        _scheduler_module = PrivescSchedulerModule()
    return _scheduler_module


__all__ = [
    "PrivescSchedulerModule",
    "PrivescTaskScheduler",
    "ScheduledPrivescChecker",
    "PrivescWorkflowEngine",
    "PrivescTask",
    "WorkflowStep",
    "WorkflowInstance",
    "WorkflowTemplate",
    "TaskPriority",
    "TaskStatus",
    "WorkflowStepStatus",
    "MachineImportance",
    "get_scheduler_module",
]
