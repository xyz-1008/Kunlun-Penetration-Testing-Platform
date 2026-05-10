"""
Windows/Linux提权辅助套件 - 强化学习优化框架
============================================
将提权过程建模为马尔可夫决策过程（MDP），通过强化学习自动学习
当前环境下的最优提权路径。

核心能力:
    1. MDP建模 - 状态/动作/奖励定义
    2. 强化学习策略优化 - 使用stable-baselines3或离线fallback
    3. 动态阈值调整 - 根据历史成功率动态调整推荐优先级
    4. 知识持久化 - 学习结果本地存储，跨项目复用

Author: 昆仑安全实验室
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# 枚举与数据模型
# =============================================================================

class RLMode(str, Enum):
    """强化学习模式"""
    STABLE_BASELINES = "stable_baselines"
    Q_LEARNING = "q_learning"
    STATIC_FALLBACK = "static_fallback"


class PrivilegeState(str, Enum):
    """权限状态"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    SYSTEM = "system"
    ROOT = "root"


@dataclass
class MDPState:
    """MDP状态

    Attributes:
        privilege_level: 当前权限级别
        os_type: 操作系统类型
        os_version: 操作系统版本
        edr_present: 是否存在EDR
        patches_missing: 缺失补丁数
        services_vulnerable: 脆弱服务数
        tokens_available: 可用令牌数
        environment_hash: 环境特征哈希
    """
    privilege_level: PrivilegeState = PrivilegeState.LOW
    os_type: str = ""
    os_version: str = ""
    edr_present: bool = False
    patches_missing: int = 0
    services_vulnerable: int = 0
    tokens_available: int = 0
    environment_hash: str = ""

    def to_tuple(self) -> Tuple:
        """转换为元组（用于Q表键）

        Returns:
            状态元组
        """
        return (
            self.privilege_level.value,
            self.os_type,
            self.edr_present,
            min(self.patches_missing, 5),
            min(self.services_vulnerable, 5),
            min(self.tokens_available, 5),
        )

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典

        Returns:
            状态字典
        """
        return {
            "privilege_level": self.privilege_level.value,
            "os_type": self.os_type,
            "os_version": self.os_version,
            "edr_present": self.edr_present,
            "patches_missing": self.patches_missing,
            "services_vulnerable": self.services_vulnerable,
            "tokens_available": self.tokens_available,
            "environment_hash": self.environment_hash,
        }


@dataclass
class ExploitAction:
    """利用动作

    Attributes:
        action_id: 动作ID
        vector_type: 利用向量类型
        tool_name: 工具名称
        risk_level: 风险等级
        stealth_score: 隐蔽性评分
        stability_score: 稳定性评分
    """
    action_id: str = ""
    vector_type: str = ""
    tool_name: str = ""
    risk_level: str = "medium"
    stealth_score: float = 0.5
    stability_score: float = 0.5

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典

        Returns:
            动作字典
        """
        return {
            "action_id": self.action_id,
            "vector_type": self.vector_type,
            "tool_name": self.tool_name,
            "risk_level": self.risk_level,
            "stealth_score": self.stealth_score,
            "stability_score": self.stability_score,
        }


@dataclass
class RLTransition:
    """RL转移记录

    Attributes:
        state: 当前状态
        action: 执行的动作
        reward: 获得的奖励
        next_state: 下一个状态
        done: 是否终止
        timestamp: 时间戳
    """
    state: MDPState = field(default_factory=MDPState)
    action: ExploitAction = field(default_factory=ExploitAction)
    reward: float = 0.0
    next_state: MDPState = field(default_factory=MDPState)
    done: bool = False
    timestamp: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典

        Returns:
            转移记录字典
        """
        return {
            "state": self.state.to_dict(),
            "action": self.action.to_dict(),
            "reward": self.reward,
            "next_state": self.next_state.to_dict(),
            "done": self.done,
            "timestamp": self.timestamp,
        }


@dataclass
class LearningResult:
    """学习结果

    Attributes:
        episodes: 训练轮数
        best_path: 最优路径
        success_rate: 成功率
        avg_reward: 平均奖励
        q_table: Q表（Q-Learning模式）
        model_path: 模型路径（SB3模式）
        learned_at: 学习时间
    """
    episodes: int = 0
    best_path: List[str] = field(default_factory=list)
    success_rate: float = 0.0
    avg_reward: float = 0.0
    q_table: Dict[str, Dict[str, float]] = field(default_factory=dict)
    model_path: str = ""
    learned_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典

        Returns:
            学习结果字典
        """
        return {
            "episodes": self.episodes,
            "best_path": self.best_path,
            "success_rate": round(self.success_rate, 4),
            "avg_reward": round(self.avg_reward, 4),
            "q_table": self.q_table,
            "model_path": self.model_path,
            "learned_at": self.learned_at,
        }


# =============================================================================
# 奖励函数
# =============================================================================

class RewardFunction:
    """奖励函数

    定义MDP的奖励机制：
    - 提权成功: +1
    - 提权失败: -1
    - 被EDR检测: -5
    - 系统影响大: -2
    - 隐蔽性好: +0.5
    """

    SUCCESS_REWARD = 1.0
    FAILURE_PENALTY = -1.0
    DETECTION_PENALTY = -5.0
    HIGH_IMPACT_PENALTY = -2.0
    STEALTH_BONUS = 0.5
    STABILITY_BONUS = 0.3

    @staticmethod
    def calculate(
        success: bool,
        detected: bool = False,
        system_impact: str = "low",
        stealth_score: float = 0.5,
        stability_score: float = 0.5,
        consecutive_failures: int = 0,
    ) -> float:
        """计算奖励值

        Args:
            success: 是否成功
            detected: 是否被检测
            system_impact: 系统影响 (low/medium/high)
            stealth_score: 隐蔽性评分
            stability_score: 稳定性评分
            consecutive_failures: 连续失败次数

        Returns:
            奖励值
        """
        reward = 0.0

        if success:
            reward += RewardFunction.SUCCESS_REWARD
            reward += stealth_score * RewardFunction.STEALTH_BONUS
            reward += stability_score * RewardFunction.STABILITY_BONUS
        else:
            reward += RewardFunction.FAILURE_PENALTY
            reward += consecutive_failures * -0.5

        if detected:
            reward += RewardFunction.DETECTION_PENALTY

        impact_map = {"low": 0, "medium": -0.5, "high": RewardFunction.HIGH_IMPACT_PENALTY}
        reward += impact_map.get(system_impact, 0)

        return reward


# =============================================================================
# Q-Learning智能体（轻量级，无需外部依赖）
# =============================================================================

class QLearningAgent:
    """Q-Learning智能体

    轻量级强化学习实现，无需外部依赖。
    使用Q表存储状态-动作值。

    Attributes:
        _q_table: Q表 {state_tuple: {action_id: q_value}}
        _alpha: 学习率
        _gamma: 折扣因子
        _epsilon: 探索率
        _actions: 可用动作列表
        _transitions: 转移记录
        _failure_counts: 动作失败计数
    """

    def __init__(
        self,
        alpha: float = 0.1,
        gamma: float = 0.9,
        epsilon: float = 0.3,
    ) -> None:
        """初始化Q-Learning智能体

        Args:
            alpha: 学习率
            gamma: 折扣因子
            epsilon: 探索率
        """
        self._q_table: Dict[Tuple, Dict[str, float]] = {}
        self._alpha: float = alpha
        self._gamma: float = gamma
        self._epsilon: float = epsilon
        self._actions: List[ExploitAction] = []
        self._transitions: List[RLTransition] = []
        self._failure_counts: Dict[str, int] = {}
        self._success_counts: Dict[str, int] = {}

    def set_actions(self, actions: List[ExploitAction]) -> None:
        """设置可用动作列表

        Args:
            actions: 动作列表
        """
        self._actions = actions

    def choose_action(self, state: MDPState) -> ExploitAction:
        """选择动作（epsilon-greedy策略）

        Args:
            state: 当前状态

        Returns:
            选择的动作
        """
        state_tuple = state.to_tuple()

        if random.random() < self._epsilon:
            return random.choice(self._actions)

        if state_tuple not in self._q_table:
            return random.choice(self._actions)

        q_values = self._q_table[state_tuple]
        best_action_id = max(q_values, key=q_values.get)

        for action in self._actions:
            if action.action_id == best_action_id:
                return action

        return random.choice(self._actions)

    def update(
        self,
        state: MDPState,
        action: ExploitAction,
        reward: float,
        next_state: MDPState,
        done: bool,
    ) -> None:
        """更新Q值

        Args:
            state: 当前状态
            action: 执行的动作
            reward: 获得的奖励
            next_state: 下一个状态
            done: 是否终止
        """
        state_tuple = state.to_tuple()
        next_state_tuple = next_state.to_tuple()

        if state_tuple not in self._q_table:
            self._q_table[state_tuple] = {
                a.action_id: 0.0 for a in self._actions
            }

        if next_state_tuple not in self._q_table:
            self._q_table[next_state_tuple] = {
                a.action_id: 0.0 for a in self._actions
            }

        current_q = self._q_table[state_tuple].get(action.action_id, 0.0)
        max_next_q = max(self._q_table[next_state_tuple].values())

        if done:
            new_q = current_q + self._alpha * (reward - current_q)
        else:
            new_q = current_q + self._alpha * (
                reward + self._gamma * max_next_q - current_q
            )

        self._q_table[state_tuple][action.action_id] = new_q

        if reward < 0:
            self._failure_counts[action.action_id] = (
                self._failure_counts.get(action.action_id, 0) + 1
            )
        else:
            self._success_counts[action.action_id] = (
                self._success_counts.get(action.action_id, 0) + 1
            )

        transition = RLTransition(
            state=state,
            action=action,
            reward=reward,
            next_state=next_state,
            done=done,
            timestamp=datetime.now().isoformat(),
        )
        self._transitions.append(transition)

    def get_best_action(self, state: MDPState) -> Optional[ExploitAction]:
        """获取当前状态下的最优动作

        Args:
            state: 当前状态

        Returns:
            最优动作或None
        """
        state_tuple = state.to_tuple()

        if state_tuple not in self._q_table:
            return None

        q_values = self._q_table[state_tuple]
        if not q_values:
            return None

        best_action_id = max(q_values, key=q_values.get)

        for action in self._actions:
            if action.action_id == best_action_id:
                return action

        return None

    def get_action_scores(self, state: MDPState) -> Dict[str, float]:
        """获取所有动作的Q值评分

        Args:
            state: 当前状态

        Returns:
            动作评分字典 {action_id: q_value}
        """
        state_tuple = state.to_tuple()

        if state_tuple not in self._q_table:
            return {a.action_id: 0.0 for a in self._actions}

        return dict(self._q_table[state_tuple])

    def get_failure_count(self, action_id: str) -> int:
        """获取动作失败次数

        Args:
            action_id: 动作ID

        Returns:
            失败次数
        """
        return self._failure_counts.get(action_id, 0)

    def is_action_disabled(self, action_id: str, threshold: int = 3) -> bool:
        """判断动作是否应被禁用

        连续失败3次后自动降权。

        Args:
            action_id: 动作ID
            threshold: 失败阈值

        Returns:
            是否应禁用
        """
        return self._failure_counts.get(action_id, 0) >= threshold

    def save(self, path: str) -> bool:
        """保存Q表到本地

        Args:
            path: 保存路径

        Returns:
            是否成功
        """
        try:
            serializable_q = {
                str(k): v for k, v in self._q_table.items()
            }

            data = {
                "q_table": serializable_q,
                "alpha": self._alpha,
                "gamma": self._gamma,
                "epsilon": self._epsilon,
                "failure_counts": self._failure_counts,
                "success_counts": self._success_counts,
                "transitions_count": len(self._transitions),
                "saved_at": datetime.now().isoformat(),
            }

            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

            logger.info(f"Q表已保存: {path}")
            return True

        except Exception as e:
            logger.error(f"Q表保存失败: {e}")
            return False

    def load(self, path: str) -> bool:
        """从本地加载Q表

        Args:
            path: 加载路径

        Returns:
            是否成功
        """
        try:
            if not os.path.exists(path):
                return False

            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)

            self._q_table = {
                eval(k): v for k, v in data.get("q_table", {}).items()
            }
            self._alpha = data.get("alpha", 0.1)
            self._gamma = data.get("gamma", 0.9)
            self._epsilon = data.get("epsilon", 0.3)
            self._failure_counts = data.get("failure_counts", {})
            self._success_counts = data.get("success_counts", {})

            logger.info(f"Q表已加载: {path}")
            return True

        except Exception as e:
            logger.error(f"Q表加载失败: {e}")
            return False

    def get_learning_result(self) -> LearningResult:
        """获取学习结果

        Returns:
            学习结果
        """
        total = len(self._transitions)
        success_count = sum(
            1 for t in self._transitions if t.reward > 0
        )

        best_path = []
        if self._transitions:
            sorted_transitions = sorted(
                self._transitions, key=lambda t: t.reward, reverse=True,
            )
            best_path = [
                t.action.action_id
                for t in sorted_transitions[:10]
                if t.reward > 0
            ]

        avg_reward = (
            sum(t.reward for t in self._transitions) / total
            if total > 0 else 0.0
        )

        serializable_q = {
            str(k): v for k, v in self._q_table.items()
        }

        return LearningResult(
            episodes=total,
            best_path=best_path,
            success_rate=success_count / total if total > 0 else 0.0,
            avg_reward=avg_reward,
            q_table=serializable_q,
            learned_at=datetime.now().isoformat(),
        )


# =============================================================================
# Stable-Baselines3适配器（可选，需要安装stable-baselines3）
# =============================================================================

class SB3Adapter:
    """Stable-Baselines3适配器

    当stable-baselines3可用时使用深度强化学习。
    否则自动回退到Q-Learning。

    Attributes:
        _available: SB3是否可用
        _model: SB3模型
        _env: 自定义环境
    """

    def __init__(self) -> None:
        """初始化SB3适配器"""
        self._available: bool = False
        self._model: Optional[Any] = None
        self._env: Optional[Any] = None

        try:
            import stable_baselines3
            self._available = True
            logger.info("Stable-Baselines3可用")
        except ImportError:
            self._available = False
            logger.info("Stable-Baselines3不可用，使用Q-Learning fallback")

    @property
    def is_available(self) -> bool:
        """SB3是否可用

        Returns:
            是否可用
        """
        return self._available

    def train(
        self,
        state_dim: int,
        action_dim: int,
        episodes: int = 100,
        model_path: str = "",
    ) -> Optional[str]:
        """训练SB3模型

        Args:
            state_dim: 状态维度
            action_dim: 动作维度
            episodes: 训练轮数
            model_path: 模型保存路径

        Returns:
            模型路径或None
        """
        if not self._available:
            return None

        try:
            from stable_baselines3 import PPO
            from stable_baselines3.common.env_util import make_vec_env

            env = self._create_env(state_dim, action_dim)
            self._env = env

            model = PPO(
                "MlpPolicy",
                env,
                verbose=0,
                learning_rate=0.001,
                n_steps=2048,
                batch_size=64,
                n_epochs=10,
            )

            model.learn(total_timesteps=episodes * 2048)

            if model_path:
                model.save(model_path)
                self._model = model
                return model_path

            return None

        except Exception as e:
            logger.error(f"SB3训练失败: {e}")
            return None

    def predict(self, state: List[float]) -> int:
        """使用SB3模型预测

        Args:
            state: 状态向量

        Returns:
            动作索引
        """
        if not self._available or self._model is None:
            return 0

        try:
            action, _ = self._model.predict(state, deterministic=True)
            return int(action)
        except Exception:
            return 0

    def _create_env(self, state_dim: int, action_dim: int) -> Any:
        """创建自定义Gym环境

        Args:
            state_dim: 状态维度
            action_dim: 动作维度

        Returns:
            Gym环境
        """
        import gymnasium as gym
        import numpy as np

        class PrivescEnv(gym.Env):
            """提权环境"""

            def __init__(self) -> None:
                super().__init__()
                self.state_dim = state_dim
                self.action_dim = action_dim
                self.action_space = gym.spaces.Discrete(action_dim)
                self.observation_space = gym.spaces.Box(
                    low=0, high=1, shape=(state_dim,), dtype=np.float32,
                )
                self.current_step = 0
                self.max_steps = 100

            def reset(self, **kwargs: Any) -> Tuple[np.ndarray, Dict[str, Any]]:
                self.current_step = 0
                state = np.zeros(self.state_dim, dtype=np.float32)
                return state, {}

            def step(
                self, action: int,
            ) -> Tuple[np.ndarray, float, bool, bool, Dict[str, Any]]:
                self.current_step += 1
                reward = -0.1
                done = self.current_step >= self.max_steps
                state = np.zeros(self.state_dim, dtype=np.float32)
                return state, reward, done, False, {}

        return PrivescEnv()


# =============================================================================
# 动态阈值管理器
# =============================================================================

class DynamicThresholdManager:
    """动态阈值管理器

    根据历史成功率动态调整各利用向量的推荐优先级。

    Attributes:
        _success_rates: 向量成功率 {vector_type: (success, total)}
        _cooldowns: 冷却期 {vector_type: expiry_timestamp}
        _global_success_rate: 全局成功率
    """

    def __init__(self) -> None:
        """初始化动态阈值管理器"""
        self._success_rates: Dict[str, Tuple[int, int]] = {}
        self._cooldowns: Dict[str, float] = {}
        self._global_success_rate: float = 0.5

    def record_attempt(
        self, vector_type: str, success: bool,
    ) -> None:
        """记录利用尝试

        Args:
            vector_type: 向量类型
            success: 是否成功
        """
        current = self._success_rates.get(vector_type, (0, 0))
        self._success_rates[vector_type] = (
            current[0] + (1 if success else 0),
            current[1] + 1,
        )

        total_success = sum(s for s, _ in self._success_rates.values())
        total_attempts = sum(t for _, t in self._success_rates.values())

        if total_attempts > 0:
            self._global_success_rate = total_success / total_attempts

    def get_priority_score(self, vector_type: str) -> float:
        """获取向量优先级评分

        Args:
            vector_type: 向量类型

        Returns:
            优先级评分 (0-1)
        """
        if vector_type in self._cooldowns:
            if time.time() < self._cooldowns[vector_type]:
                return 0.0
            else:
                del self._cooldowns[vector_type]

        success, total = self._success_rates.get(vector_type, (0, 0))

        if total == 0:
            return self._global_success_rate

        rate = success / total

        consecutive_failures = total - success
        if consecutive_failures >= 3:
            self._cooldowns[vector_type] = time.time() + 3600
            return 0.0

        return rate

    def get_vector_rankings(self) -> List[Dict[str, Any]]:
        """获取向量排名

        Returns:
            排名列表
        """
        rankings = []

        for vector_type, (success, total) in self._success_rates.items():
            rate = success / total if total > 0 else 0.0
            is_disabled = vector_type in self._cooldowns

            rankings.append({
                "vector_type": vector_type,
                "success_rate": round(rate, 4),
                "total_attempts": total,
                "success_count": success,
                "disabled": is_disabled,
                "priority_score": self.get_priority_score(vector_type),
            })

        rankings.sort(key=lambda x: x["priority_score"], reverse=True)
        return rankings

    def save(self, path: str) -> bool:
        """保存阈值数据

        Args:
            path: 保存路径

        Returns:
            是否成功
        """
        try:
            data = {
                "success_rates": {
                    k: list(v) for k, v in self._success_rates.items()
                },
                "global_success_rate": self._global_success_rate,
                "saved_at": datetime.now().isoformat(),
            }

            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

            return True

        except Exception as e:
            logger.error(f"阈值数据保存失败: {e}")
            return False

    def load(self, path: str) -> bool:
        """加载阈值数据

        Args:
            path: 加载路径

        Returns:
            是否成功
        """
        try:
            if not os.path.exists(path):
                return False

            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)

            self._success_rates = {
                k: tuple(v) for k, v in data.get("success_rates", {}).items()
            }
            self._global_success_rate = data.get("global_success_rate", 0.5)

            return True

        except Exception as e:
            logger.error(f"阈值数据加载失败: {e}")
            return False


# =============================================================================
# 主强化学习框架
# =============================================================================

class PrivescRLFramework:
    """提权强化学习框架

    整合Q-Learning、SB3和动态阈值管理。

    Attributes:
        _q_agent: Q-Learning智能体
        _sb3_adapter: SB3适配器
        _threshold_manager: 动态阈值管理器
        _mode: 当前模式
        _knowledge_path: 知识持久化路径
    """

    def __init__(
        self,
        knowledge_path: Optional[str] = None,
        mode: RLMode = RLMode.Q_LEARNING,
    ) -> None:
        """初始化强化学习框架

        Args:
            knowledge_path: 知识持久化路径
            mode: 强化学习模式
        """
        self._q_agent = QLearningAgent()
        self._sb3_adapter = SB3Adapter()
        self._threshold_manager = DynamicThresholdManager()
        self._mode = mode
        self._knowledge_path = knowledge_path or os.path.join(
            os.path.expanduser("~"), ".kunlun", "privesc_rl",
        )

        self._load_knowledge()

    async def select_action(
        self,
        state: MDPState,
        available_actions: List[ExploitAction],
    ) -> ExploitAction:
        """选择利用动作

        Args:
            state: 当前状态
            available_actions: 可用动作列表

        Returns:
            选择的动作
        """
        self._q_agent.set_actions(available_actions)

        if self._mode == RLMode.STABLE_BASELINES and self._sb3_adapter.is_available:
            return await self._select_action_sb3(state, available_actions)
        else:
            return self._q_agent.choose_action(state)

    async def _select_action_sb3(
        self,
        state: MDPState,
        actions: List[ExploitAction],
    ) -> ExploitAction:
        """使用SB3选择动作

        Args:
            state: 当前状态
            actions: 动作列表

        Returns:
            选择的动作
        """
        state_vector = self._state_to_vector(state)
        action_idx = self._sb3_adapter.predict(state_vector)

        if 0 <= action_idx < len(actions):
            return actions[action_idx]

        return self._q_agent.choose_action(state)

    def record_outcome(
        self,
        state: MDPState,
        action: ExploitAction,
        success: bool,
        detected: bool = False,
        system_impact: str = "low",
    ) -> float:
        """记录利用结果

        Args:
            state: 当前状态
            action: 执行的动作
            success: 是否成功
            detected: 是否被检测
            system_impact: 系统影响

        Returns:
            计算的奖励值
        """
        reward = RewardFunction.calculate(
            success=success,
            detected=detected,
            system_impact=system_impact,
            stealth_score=action.stealth_score,
            stability_score=action.stability_score,
            consecutive_failures=self._q_agent.get_failure_count(action.action_id),
        )

        next_state = MDPState(
            privilege_level=(
                PrivilegeState.SYSTEM if success else state.privilege_level
            ),
            os_type=state.os_type,
            os_version=state.os_version,
            edr_present=state.edr_present,
            patches_missing=state.patches_missing,
            services_vulnerable=state.services_vulnerable,
            tokens_available=state.tokens_available,
            environment_hash=state.environment_hash,
        )

        self._q_agent.update(
            state=state,
            action=action,
            reward=reward,
            next_state=next_state,
            done=success,
        )

        self._threshold_manager.record_attempt(action.vector_type, success)

        return reward

    def get_recommendations(
        self, state: MDPState,
    ) -> List[Dict[str, Any]]:
        """获取推荐利用向量

        Args:
            state: 当前状态

        Returns:
            推荐列表
        """
        scores = self._q_agent.get_action_scores(state)

        recommendations = []
        for action_id, q_value in scores.items():
            priority = self._threshold_manager.get_priority_score(
                self._get_vector_type(action_id),
            )
            is_disabled = self._q_agent.is_action_disabled(action_id)

            recommendations.append({
                "action_id": action_id,
                "q_value": round(q_value, 4),
                "priority_score": round(priority, 4),
                "disabled": is_disabled,
                "combined_score": round(q_value * 0.6 + priority * 0.4, 4),
            })

        recommendations.sort(key=lambda x: x["combined_score"], reverse=True)
        return recommendations

    def save_knowledge(self) -> bool:
        """保存学习知识

        Returns:
            是否成功
        """
        q_path = os.path.join(self._knowledge_path, "q_table.json")
        threshold_path = os.path.join(self._knowledge_path, "thresholds.json")

        q_saved = self._q_agent.save(q_path)
        t_saved = self._threshold_manager.save(threshold_path)

        return q_saved and t_saved

    def _load_knowledge(self) -> None:
        """加载学习知识"""
        q_path = os.path.join(self._knowledge_path, "q_table.json")
        threshold_path = os.path.join(self._knowledge_path, "thresholds.json")

        self._q_agent.load(q_path)
        self._threshold_manager.load(threshold_path)

    def _state_to_vector(self, state: MDPState) -> List[float]:
        """将状态转换为向量

        Args:
            state: MDP状态

        Returns:
            状态向量
        """
        privilege_map = {
            PrivilegeState.LOW: 0.0,
            PrivilegeState.MEDIUM: 0.33,
            PrivilegeState.HIGH: 0.66,
            PrivilegeState.SYSTEM: 1.0,
            PrivilegeState.ROOT: 1.0,
        }

        return [
            privilege_map.get(state.privilege_level, 0.0),
            1.0 if state.edr_present else 0.0,
            min(state.patches_missing / 10.0, 1.0),
            min(state.services_vulnerable / 10.0, 1.0),
            min(state.tokens_available / 10.0, 1.0),
        ]

    def _get_vector_type(self, action_id: str) -> str:
        """获取动作对应的向量类型

        Args:
            action_id: 动作ID

        Returns:
            向量类型
        """
        for action in self._q_agent._actions:
            if action.action_id == action_id:
                return action.vector_type
        return action_id

    def get_statistics(self) -> Dict[str, Any]:
        """获取学习统计

        Returns:
            统计信息
        """
        learning_result = self._q_agent.get_learning_result()
        vector_rankings = self._threshold_manager.get_vector_rankings()

        return {
            "mode": self._mode.value,
            "sb3_available": self._sb3_adapter.is_available,
            "learning_result": learning_result.to_dict(),
            "vector_rankings": vector_rankings,
            "knowledge_path": self._knowledge_path,
        }


# =============================================================================
# 全局单例
# =============================================================================

_rl_framework: Optional[PrivescRLFramework] = None


def get_rl_framework(
    knowledge_path: Optional[str] = None,
    mode: RLMode = RLMode.Q_LEARNING,
) -> PrivescRLFramework:
    """获取强化学习框架全局单例

    Args:
        knowledge_path: 知识持久化路径
        mode: 强化学习模式

    Returns:
        PrivescRLFramework 实例
    """
    global _rl_framework
    if _rl_framework is None:
        _rl_framework = PrivescRLFramework(knowledge_path, mode)
    return _rl_framework


__all__ = [
    "PrivescRLFramework",
    "QLearningAgent",
    "SB3Adapter",
    "DynamicThresholdManager",
    "RewardFunction",
    "MDPState",
    "ExploitAction",
    "RLTransition",
    "LearningResult",
    "PrivilegeState",
    "RLMode",
    "get_rl_framework",
]
