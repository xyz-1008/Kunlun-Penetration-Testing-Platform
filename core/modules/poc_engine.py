"""
PoC验证模块核心引擎
支持Python脚本和YAML声明式PoC
"""

import os
import sys
import importlib.util
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import yaml

logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    """风险等级"""
    CRITICAL = "严重"
    HIGH = "高危"
    MEDIUM = "中危"
    LOW = "低危"
    INFO = "信息"


class PoCType(Enum):
    """PoC类型"""
    PYTHON = "python"
    YAML = "yaml"


@dataclass
class PoCMetadata:
    """PoC元数据"""
    name: str
    cve: str = ""
    product: str = ""
    version_range: str = ""
    risk_level: RiskLevel = RiskLevel.INFO
    tags: List[str] = field(default_factory=list)
    description: str = ""
    author: str = ""
    references: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)


@dataclass
class PoCResult:
    """PoC验证结果"""
    vulnerable: bool
    evidence: str = ""
    payload: str = ""
    response_summary: str = ""
    confidence: str = "unknown"
    poc_name: str = ""
    cve: str = ""
    risk_level: str = ""
    target: str = ""
    error: str = ""


class PoCLoader:
    """PoC加载器"""
    
    def __init__(self, poc_dir: str):
        self.poc_dir = Path(poc_dir)
        self.poc_dir.mkdir(parents=True, exist_ok=True)
        self._pocs: Dict[str, Dict[str, Any]] = {}
        
    def load_all_pocs(self) -> Dict[str, Dict[str, Any]]:
        """加载所有PoC"""
        self._pocs.clear()
        
        if not self.poc_dir.exists():
            logger.warning(f"PoC目录不存在: {self.poc_dir}")
            return self._pocs
        
        for file_path in self.poc_dir.rglob("*"):
            if file_path.suffix == ".py" and not file_path.name.startswith("_"):
                self._load_python_poc(file_path)
            elif file_path.suffix in [".yaml", ".yml"]:
                self._load_yaml_poc(file_path)
        
        logger.info(f"加载了 {len(self._pocs)} 个PoC")
        return self._pocs
    
    def _load_python_poc(self, file_path: Path):
        """加载Python格式PoC"""
        try:
            spec = importlib.util.spec_from_file_location(
                f"poc_{file_path.stem}", file_path
            )
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            if hasattr(module, "metadata"):
                metadata = module.metadata
            else:
                metadata = self._extract_python_metadata(module)
            
            if hasattr(module, "verify"):
                poc_id = metadata.get("name", file_path.stem)
                self._pocs[poc_id] = {
                    "type": PoCType.PYTHON,
                    "module": module,
                    "metadata": metadata,
                    "file_path": str(file_path),
                }
                logger.info(f"加载Python PoC: {poc_id}")
        except Exception as e:
            logger.error(f"加载Python PoC失败 {file_path}: {e}")
    
    def _load_yaml_poc(self, file_path: Path):
        """加载YAML格式PoC"""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                yaml_data = yaml.safe_load(f)
            
            if not yaml_data or not isinstance(yaml_data, dict):
                return
            
            metadata = {
                "name": yaml_data.get("name", file_path.stem),
                "cve": yaml_data.get("cve", ""),
                "product": yaml_data.get("product", ""),
                "version_range": yaml_data.get("version_range", ""),
                "risk_level": RiskLevel(yaml_data.get("risk_level", "info")),
                "tags": yaml_data.get("tags", []),
                "description": yaml_data.get("description", ""),
                "author": yaml_data.get("author", ""),
                "references": yaml_data.get("references", []),
                "dependencies": yaml_data.get("dependencies", []),
            }
            
            poc_id = metadata["name"]
            self._pocs[poc_id] = {
                "type": PoCType.YAML,
                "yaml_data": yaml_data,
                "metadata": metadata,
                "file_path": str(file_path),
            }
            logger.info(f"加载YAML PoC: {poc_id}")
        except Exception as e:
            logger.error(f"加载YAML PoC失败 {file_path}: {e}")
    
    def _extract_python_metadata(self, module) -> Dict[str, Any]:
        """从Python模块提取元数据"""
        return {
            "name": getattr(module, "__name__", "unknown"),
            "cve": getattr(module, "CVE", ""),
            "product": getattr(module, "PRODUCT", ""),
            "version_range": getattr(module, "VERSION_RANGE", ""),
            "risk_level": RiskLevel(getattr(module, "RISK_LEVEL", "info")),
            "tags": getattr(module, "TAGS", []),
            "description": getattr(module, "DESCRIPTION", ""),
            "author": getattr(module, "AUTHOR", ""),
            "references": getattr(module, "REFERENCES", []),
            "dependencies": getattr(module, "DEPENDENCIES", []),
        }
    
    def get_poc(self, poc_id: str) -> Optional[Dict[str, Any]]:
        """获取指定PoC"""
        return self._pocs.get(poc_id)
    
    def get_all_pocs(self) -> Dict[str, Dict[str, Any]]:
        """获取所有PoC"""
        return self._pocs.copy()
    
    def get_poc_ids(self) -> List[str]:
        """获取所有PoC ID"""
        return list(self._pocs.keys())
