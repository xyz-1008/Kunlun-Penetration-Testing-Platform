"""
专业级JWT (JSON Web Token) 工具模块
基于20年渗透测试专家经验，提供生成、验证、分析功能
"""

import logging
import base64
import json
import hmac
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum, auto

logger = logging.getLogger(__name__)


class JWTAlgorithm(Enum):
    """JWT支持的签名算法"""
    HS256 = auto()
    HS384 = auto()
    HS512 = auto()
    RS256 = auto()
    RS384 = auto()
    RS512 = auto()
    
    @classmethod
    def from_string(cls, alg_str: str) -> 'JWTAlgorithm':
        """从字符串获取算法枚举"""
        alg_str = alg_str.upper()
        try:
            return cls[alg_str]
        except KeyError:
            logger.warning(f"未知算法: {alg_str}, 默认使用HS256")
            return cls.HS256
    
    def __str__(self) -> str:
        return self.name


@dataclass
class JWTConfig:
    """JWT配置数据结构"""
    issuer: Optional[str] = None  # 签发者 (iss)
    audience: Optional[str] = None  # 受众 (aud)
    subject: Optional[str] = None  # 主题 (sub)
    expires_in: int = 3600  # 过期时间（秒），默认1小时
    not_before: Optional[int] = None  # 生效时间（秒）
    jwt_id: Optional[str] = None  # JWT ID
    algorithm: JWTAlgorithm = JWTAlgorithm.HS256  # 签名算法
    
    def __post_init__(self):
        """验证配置"""
        if self.expires_in <= 0:
            raise ValueError("expires_in必须大于0")


@dataclass
class JWTPayload:
    """JWT载荷数据"""
    header: Dict[str, Any] = field(default_factory=dict)
    payload: Dict[str, Any] = field(default_factory=dict)
    signature: str = ""
    raw_token: str = ""
    is_valid: bool = False
    validation_errors: List[str] = field(default_factory=list)


class JWTUtils:
    """JWT工具类 - 共享的编码/解码方法"""
    
    @staticmethod
    def base64url_encode(data: bytes) -> str:
        """Base64 URL安全编码"""
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')
    
    @staticmethod
    def base64url_decode(data: str) -> bytes:
        """Base64 URL安全解码"""
        try:
            padding_needed = 4 - len(data) % 4
            if padding_needed != 4:
                data += '=' * padding_needed
            return base64.urlsafe_b64decode(data)
        except Exception as e:
            logger.error(f"Base64解码失败: {str(e)}")
            raise ValueError(f"Base64解码错误: {str(e)}")


class JWTGenerator:
    """专业级JWT生成器"""
    
    @staticmethod
    def _sign_hs256(header_b64: str, payload_b64: str, secret: str) -> str:
        """HS256签名"""
        try:
            message = f"{header_b64}.{payload_b64}".encode('utf-8')
            secret_bytes = secret.encode('utf-8')
            signature = hmac.new(secret_bytes, message, hashlib.sha256).digest()
            return JWTUtils.base64url_encode(signature)
        except Exception as e:
            logger.error(f"HS256签名失败: {str(e)}")
            raise ValueError(f"签名失败: {str(e)}")
    
    @staticmethod
    def _sign_hs384(header_b64: str, payload_b64: str, secret: str) -> str:
        """HS384签名"""
        try:
            message = f"{header_b64}.{payload_b64}".encode('utf-8')
            secret_bytes = secret.encode('utf-8')
            signature = hmac.new(secret_bytes, message, hashlib.sha384).digest()
            return JWTUtils.base64url_encode(signature)
        except Exception as e:
            logger.error(f"HS384签名失败: {str(e)}")
            raise ValueError(f"签名失败: {str(e)}")
    
    @staticmethod
    def _sign_hs512(header_b64: str, payload_b64: str, secret: str) -> str:
        """HS512签名"""
        try:
            message = f"{header_b64}.{payload_b64}".encode('utf-8')
            secret_bytes = secret.encode('utf-8')
            signature = hmac.new(secret_bytes, message, hashlib.sha512).digest()
            return JWTUtils.base64url_encode(signature)
        except Exception as e:
            logger.error(f"HS512签名失败: {str(e)}")
            raise ValueError(f"签名失败: {str(e)}")
    
    @staticmethod
    def generate(
        payload: Dict[str, Any],
        secret: str,
        config: Optional[JWTConfig] = None,
        custom_claims: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        生成JWT Token
        
        Args:
            payload: 用户自定义载荷数据
            secret: 密钥
            config: JWT配置
            custom_claims: 自定义声明
        
        Returns:
            JWT Token字符串
        """
        config = config or JWTConfig()
        
        if not secret or len(secret.strip()) < 8:
            raise ValueError("密钥长度至少为8个字符")
        
        # 构建标准声明
        now = datetime.utcnow()
        jwt_payload = payload.copy()
        
        # 添加标准JWT声明
        if config.issuer:
            jwt_payload['iss'] = config.issuer
        if config.audience:
            jwt_payload['aud'] = config.audience
        if config.subject:
            jwt_payload['sub'] = config.subject
        
        # 时间相关声明
        jwt_payload['iat'] = int(now.timestamp())
        jwt_payload['exp'] = int((now + timedelta(seconds=config.expires_in)).timestamp())
        if config.not_before:
            jwt_payload['nbf'] = int((now + timedelta(seconds=config.not_before)).timestamp())
        if config.jwt_id:
            jwt_payload['jti'] = config.jwt_id
        
        # 添加自定义声明
        if custom_claims:
            jwt_payload.update(custom_claims)
        
        # 构建Header
        header = {
            "alg": config.algorithm.name,
            "typ": "JWT"
        }
        
        # 编码Header和Payload
        header_b64 = JWTUtils.base64url_encode(json.dumps(header, ensure_ascii=False).encode('utf-8'))
        payload_b64 = JWTUtils.base64url_encode(json.dumps(jwt_payload, ensure_ascii=False).encode('utf-8'))
        
        # 签名
        if config.algorithm == JWTAlgorithm.HS256:
            signature = JWTGenerator._sign_hs256(header_b64, payload_b64, secret)
        elif config.algorithm == JWTAlgorithm.HS384:
            signature = JWTGenerator._sign_hs384(header_b64, payload_b64, secret)
        elif config.algorithm == JWTAlgorithm.HS512:
            signature = JWTGenerator._sign_hs512(header_b64, payload_b64, secret)
        else:
            logger.warning(f"暂不支持算法: {config.algorithm}, 使用HS256")
            signature = JWTGenerator._sign_hs256(header_b64, payload_b64, secret)
        
        token = f"{header_b64}.{payload_b64}.{signature}"
        logger.info(f"成功生成JWT Token，算法: {config.algorithm.name}")
        return token
    
    @staticmethod
    def refresh(
        token: str,
        secret: str,
        new_expires_in: int = 3600,
        config: Optional[JWTConfig] = None
    ) -> Tuple[Optional[str], Optional[JWTPayload]]:
        """刷新JWT Token
        
        Args:
            token: 原Token
            secret: 密钥
            new_expires_in: 新的过期时间
            config: 配置
        
        Returns:
            (新Token, 解析的载荷)
        """
        try:
            if new_expires_in <= 0:
                raise ValueError("过期时间必须大于0")
            
            payload = JWTParser.parse(token, secret, skip_expired=True)
            
            if not payload.is_valid and len(payload.validation_errors) > 0:
                if not any('已过期' in err for err in payload.validation_errors):
                    logger.warning("Token验证失败，无法刷新")
                    return None, payload
            
            now = datetime.utcnow()
            new_payload = payload.payload.copy()
            new_payload['iat'] = int(now.timestamp())
            new_payload['exp'] = int((now + timedelta(seconds=new_expires_in)).timestamp())
            
            config = config or JWTConfig(expires_in=new_expires_in)
            new_token = JWTGenerator.generate(new_payload, secret, config)
            
            logger.info("成功刷新JWT Token")
            return new_token, payload
            
        except Exception as e:
            logger.error(f"Token刷新失败: {str(e)}", exc_info=True)
            return None, None


class JWTParser:
    """专业级JWT解析器"""
    
    @staticmethod
    def _verify_hs256(header_b64: str, payload_b64: str, signature_b64: str, secret: str) -> bool:
        """验证HS256签名"""
        try:
            message = f"{header_b64}.{payload_b64}".encode('utf-8')
            secret_bytes = secret.encode('utf-8')
            expected_signature = hmac.new(secret_bytes, message, hashlib.sha256).digest()
            expected_b64 = JWTUtils.base64url_encode(expected_signature)
            return hmac.compare_digest(expected_b64, signature_b64)
        except Exception as e:
            logger.error(f"签名验证失败: {str(e)}")
            return False
    
    @staticmethod
    def _verify_hs384(header_b64: str, payload_b64: str, signature_b64: str, secret: str) -> bool:
        """验证HS384签名"""
        try:
            message = f"{header_b64}.{payload_b64}".encode('utf-8')
            secret_bytes = secret.encode('utf-8')
            expected_signature = hmac.new(secret_bytes, message, hashlib.sha384).digest()
            expected_b64 = JWTUtils.base64url_encode(expected_signature)
            return hmac.compare_digest(expected_b64, signature_b64)
        except Exception as e:
            logger.error(f"签名验证失败: {str(e)}")
            return False
    
    @staticmethod
    def _verify_hs512(header_b64: str, payload_b64: str, signature_b64: str, secret: str) -> bool:
        """验证HS512签名"""
        try:
            message = f"{header_b64}.{payload_b64}".encode('utf-8')
            secret_bytes = secret.encode('utf-8')
            expected_signature = hmac.new(secret_bytes, message, hashlib.sha512).digest()
            expected_b64 = JWTUtils.base64url_encode(expected_signature)
            return hmac.compare_digest(expected_b64, signature_b64)
        except Exception as e:
            logger.error(f"签名验证失败: {str(e)}")
            return False
    
    @staticmethod
    def parse(token: str, secret: Optional[str] = None, skip_expired: bool = False) -> JWTPayload:
        """
        解析JWT Token
        
        Args:
            token: JWT Token字符串
            secret: 密钥（可选，用于验证签名）
            skip_expired: 是否跳过过期检查
        
        Returns:
            JWTPayload对象
        """
        errors = []
        
        if not token or not token.strip():
            return JWTPayload(
                validation_errors=["Token不能为空"], is_valid=False, raw_token=token
            )
        
        try:
            parts = token.split('.')
            if len(parts) != 3:
                errors.append("Token格式错误，需要包含3个部分")
                return JWTPayload(
                    header={}, payload={}, signature="", raw_token=token, 
                    is_valid=False, validation_errors=errors
                )
            
            header_b64, payload_b64, signature_b64 = parts
            
            header = {}
            try:
                header_json = JWTUtils.base64url_decode(header_b64)
                header = json.loads(header_json.decode('utf-8', errors='ignore'))
            except Exception as e:
                errors.append(f"Header解码失败: {str(e)}")
            
            payload = {}
            try:
                payload_json = JWTUtils.base64url_decode(payload_b64)
                payload = json.loads(payload_json.decode('utf-8', errors='ignore'))
            except Exception as e:
                errors.append(f"Payload解码失败: {str(e)}")
            
            is_valid = len(errors) == 0
            if secret and is_valid:
                alg = header.get('alg', 'HS256')
                if alg == 'HS256':
                    if not JWTParser._verify_hs256(header_b64, payload_b64, signature_b64, secret):
                        errors.append("签名验证失败")
                        is_valid = False
                elif alg == 'HS384':
                    if not JWTParser._verify_hs384(header_b64, payload_b64, signature_b64, secret):
                        errors.append("签名验证失败")
                        is_valid = False
                elif alg == 'HS512':
                    if not JWTParser._verify_hs512(header_b64, payload_b64, signature_b64, secret):
                        errors.append("签名验证失败")
                        is_valid = False
                elif alg != 'none':
                    errors.append(f"不支持的算法: {alg}")
                    is_valid = False
            
            if 'exp' in payload and not skip_expired:
                try:
                    exp_time = datetime.fromtimestamp(payload['exp'])
                    now = datetime.utcnow()
                    if now > exp_time:
                        errors.append(f"Token已过期，过期时间: {exp_time}")
                        is_valid = False
                except Exception as e:
                    errors.append(f"过期时间格式错误: {str(e)}")
            
            return JWTPayload(
                header=header, payload=payload, signature=signature_b64,
                raw_token=token, is_valid=is_valid, validation_errors=errors
            )
            
        except Exception as e:
            errors.append(f"Token解析异常: {str(e)}")
            logger.error(f"解析Token时发生异常: {str(e)}", exc_info=True)
            return JWTPayload(
                header={}, payload={}, signature="", raw_token=token, 
                is_valid=False, validation_errors=errors
            )
    
    @staticmethod
    def analyze(token: str) -> Dict[str, Any]:
        """
        分析JWT Token的安全分析
        
        Returns:
            安全分析结果
        """
        result: Dict[str, Any] = {
            "is_jwt": False,
            "header": {},
            "payload": {},
            "security_issues": [],
            "recommendations": []
        }
        
        try:
            parts = token.split('.')
            if len(parts) != 3:
                result["security_issues"].append("格式错误")
                return result
            
            result["is_jwt"] = True
            
            try:
                header = json.loads(JWTUtils.base64url_decode(parts[0]).decode('utf-8', errors='ignore'))
                result["header"] = header
                
                alg = header.get('alg')
                if alg == 'none':
                    result["security_issues"].append("使用了None算法（无签名）")
                    result["recommendations"].append("使用HS256或RS256算法")
                
                if alg in ['HS256', 'HS384', 'HS512']:
                    result["security_issues"].append("使用了HS算法，密钥泄漏风险")
                    result["recommendations"].append("生产环境推荐RS算法")
                
            except Exception as e:
                result["security_issues"].append(f"Header解析失败: {str(e)}")
            
            try:
                payload = json.loads(JWTUtils.base64url_decode(parts[1]).decode('utf-8', errors='ignore'))
                result["payload"] = payload
                
                if 'exp' not in payload:
                    result["security_issues"].append("缺少过期时间(exp)")
                    result["recommendations"].append("添加过期时间防止Token无限期使用")
                
                sensitive_fields = ['password', 'secret', 'credit_card', 'ssn', 'private_key']
                for field in sensitive_fields:
                    if field in str(payload).lower():
                        result["security_issues"].append(f"Payload中包含敏感字段: {field}")
                        result["recommendations"].append("敏感信息应避免放在JWT中")
            
            except Exception as e:
                result["security_issues"].append(f"Payload解析失败: {str(e)}")
        
        except Exception as e:
            result["security_issues"].append(f"分析失败: {str(e)}")
            logger.error(f"Token分析失败: {str(e)}")
        
        return result


class JWTKeyManager:
    """专业级JWT密钥管理器"""
    
    def __init__(self):
        self.keys: Dict[str, Dict[str, Any]] = {}
        self.audit_log: List[Dict[str, Any]] = []
        logger.info("JWT密钥管理器初始化完成")
    
    def generate_key(self, key_id: str, algorithm: JWTAlgorithm = JWTAlgorithm.HS256, length: int = 32) -> str:
        """生成安全密钥"""
        if length < 16:
            raise ValueError("密钥长度至少为16个字符")
        
        key = secrets.token_urlsafe(length)
        self.keys[key_id] = {
            "key": key,
            "algorithm": algorithm.name,
            "created_at": datetime.utcnow().isoformat(),
            "last_used": None,
            "usage_count": 0
        }
        self._log_audit("generate_key", {"key_id": key_id, "algorithm": algorithm.name})
        logger.info(f"生成密钥: {key_id}")
        return key
    
    def get_key(self, key_id: str) -> Optional[str]:
        """获取密钥"""
        if key_id in self.keys:
            key_data = self.keys[key_id]
            key_data["last_used"] = datetime.utcnow().isoformat()
            key_data["usage_count"] += 1
            self._log_audit("get_key", {"key_id": key_id})
            return key_data["key"]
        logger.warning(f"密钥不存在: {key_id}")
        return None
    
    def rotate_key(self, key_id: str, new_length: int = 32) -> Optional[str]:
        """轮换密钥"""
        if key_id in self.keys:
            alg_name = self.keys[key_id]["algorithm"]
            try:
                algorithm = JWTAlgorithm[alg_name]
            except KeyError:
                algorithm = JWTAlgorithm.HS256
            
            new_key = self.generate_key(key_id, algorithm, new_length)
            self._log_audit("rotate_key", {"key_id": key_id})
            logger.info(f"密钥轮换完成: {key_id}")
            return new_key
        return None
    
    def revoke_key(self, key_id: str) -> bool:
        """撤销密钥"""
        if key_id in self.keys:
            del self.keys[key_id]
            self._log_audit("revoke_key", {"key_id": key_id})
            logger.info(f"密钥已撤销: {key_id}")
            return True
        return False
    
    def list_keys(self) -> List[Dict[str, Any]]:
        """列出所有密钥信息（不含实际密钥）"""
        return [
            {
                "key_id": kid,
                "algorithm": data["algorithm"],
                "created_at": data["created_at"],
                "last_used": data["last_used"],
                "usage_count": data["usage_count"]
            }
            for kid, data in self.keys.items()
        ]
    
    def _log_audit(self, action: str, details: Dict[str, Any]) -> None:
        """审计日志"""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "action": action,
            "details": details
        }
        self.audit_log.append(log_entry)
        logger.debug(f"审计日志: {action}")
    
    def get_audit_log(self, limit: int = 100) -> List[Dict[str, Any]]:
        """获取审计日志，支持数量限制"""
        return self.audit_log[-limit:].copy()


class SecureCodingGuide:
    """安全编码最佳实践"""
    
    @staticmethod
    def get_owasp_guidelines() -> Dict[str, List[str]]:
        """获取OWASP安全编码指南"""
        return {
            "输入验证": [
                "验证所有输入数据的类型、长度、格式和范围",
                "使用白名单验证而非黑名单",
                "拒绝无效输入而非尝试修复",
                "验证文件上传的类型和大小",
            ],
            "输出编码": [
                "根据输出上下文进行适当编码",
                "HTML编码防止XSS攻击",
                "URL编码防止注入攻击",
                "JSON编码防止注入",
            ],
            "身份验证": [
                "使用强密码策略",
                "实现多因素认证",
                "安全存储密码（使用bcrypt/Argon2）",
                "实现会话超时",
            ],
            "密钥管理": [
                "定期轮换密钥",
                "使用强随机数生成器",
                "密钥分离存储",
                "实现密钥访问审计",
            ],
            "错误处理": [
                "不要暴露敏感信息",
                "记录详细错误到日志",
                "向用户显示通用错误信息",
            ]
        }
    
    @staticmethod
    def get_security_best_practices() -> Dict[str, str]:
        """获取安全最佳实践"""
        return {
            "数据传输加密": "始终使用TLS 1.2+，禁用旧版本",
            "存储加密": "敏感数据静态加密",
            "输入验证": "严格验证所有输入",
            "输出编码": "根据上下文正确编码输出",
            "密钥管理": "实现密钥生命周期管理",
            "审计日志": "记录所有安全相关操作",
            "访问控制": "最小权限原则",
        }

