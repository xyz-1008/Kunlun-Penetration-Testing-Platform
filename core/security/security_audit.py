"""
安全审计模块 - 基于20年渗透测试经验的安全加固
识别和修复代码中的安全漏洞
"""

import ast
import logging
import re
from typing import Dict, List, Set, Tuple, Any
from pathlib import Path

logger = logging.getLogger(__name__)

class SecurityVulnerability:
    """安全漏洞定义"""
    
    def __init__(self, vulnerability_type: str, severity: str, 
                 description: str, file_path: str, line_number: int,
                 code_snippet: str, fix_suggestion: str):
        self.vulnerability_type = vulnerability_type
        self.severity = severity  # high, medium, low
        self.description = description
        self.file_path = file_path
        self.line_number = line_number
        self.code_snippet = code_snippet
        self.fix_suggestion = fix_suggestion
        
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'type': self.vulnerability_type,
            'severity': self.severity,
            'description': self.description,
            'file_path': self.file_path,
            'line_number': self.line_number,
            'code_snippet': self.code_snippet,
            'fix_suggestion': self.fix_suggestion
        }

class SecurityAuditor:
    """安全审计器"""
    
    def __init__(self):
        self.vulnerabilities: List[SecurityVulnerability] = []
        self.patterns = self._load_security_patterns()
        
    def _load_security_patterns(self) -> Dict[str, Dict]:
        """加载安全检测模式"""
        return {
            'sql_injection': {
                'pattern': r'(?i)(select|insert|update|delete|drop).*\%s',
                'severity': 'high',
                'description': '潜在的SQL注入漏洞',
                'fix': '使用参数化查询或ORM'
            },
            'command_injection': {
                'pattern': r'(?i)(os\.system|subprocess\.call|exec|eval).*\%s',
                'severity': 'high',
                'description': '潜在的命令注入漏洞',
                'fix': '使用安全的命令执行方法'
            },
            'xss_vulnerability': {
                'pattern': r'(?i)(<script>|javascript:|on\w+\s*=)',
                'severity': 'medium',
                'description': '潜在的XSS漏洞',
                'fix': '实施输出编码和内容安全策略'
            },
            'hardcoded_secrets': {
                'pattern': r'(password|pwd|secret|key|token)\s*=\s*["\'][^"\']{8,}["\']',
                'severity': 'high',
                'description': '硬编码的敏感信息',
                'fix': '使用环境变量或配置文件'
            },
            'weak_crypto': {
                'pattern': r'(?i)(md5|sha1|base64_encode)',
                'severity': 'medium',
                'description': '弱加密算法使用',
                'fix': '使用强加密算法如SHA256、AES'
            },
            'insecure_random': {
                'pattern': r'(?i)(random\.randint|random\.choice)',
                'severity': 'medium',
                'description': '不安全的随机数生成',
                'fix': '使用secrets模块生成安全随机数'
            },
            'path_traversal': {
                'pattern': r'(?i)(\.\./|\.\.\\|~/|/etc/|/var/)',
                'severity': 'high',
                'description': '路径遍历漏洞',
                'fix': '验证和清理文件路径'
            },
            'insecure_deserialization': {
                'pattern': r'(?i)(pickle\.loads|marshal\.loads)',
                'severity': 'high',
                'description': '不安全的反序列化',
                'fix': '避免反序列化不可信数据'
            }
        }
    
    def audit_file(self, file_path: str) -> List[SecurityVulnerability]:
        """审计单个文件"""
        vulnerabilities = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # 模式匹配检测
            vulnerabilities.extend(self._pattern_match(content, file_path))
            
            # AST分析检测
            vulnerabilities.extend(self._ast_analysis(content, file_path))
            
        except Exception as e:
            logger.error(f"审计文件失败 {file_path}: {e}")
            
        return vulnerabilities
    
    def _pattern_match(self, content: str, file_path: str) -> List[SecurityVulnerability]:
        """模式匹配检测"""
        vulnerabilities = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for vuln_type, pattern_info in self.patterns.items():
                if re.search(pattern_info['pattern'], line):
                    vulnerability = SecurityVulnerability(
                        vulnerability_type=vuln_type,
                        severity=pattern_info['severity'],
                        description=pattern_info['description'],
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=line.strip(),
                        fix_suggestion=pattern_info['fix']
                    )
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _ast_analysis(self, content: str, file_path: str) -> List[SecurityVulnerability]:
        """AST分析检测"""
        vulnerabilities = []
        
        try:
            tree = ast.parse(content)
            
            for node in ast.walk(tree):
                # 检测eval使用
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    if node.func.id == 'eval':
                        vulnerability = SecurityVulnerability(
                            vulnerability_type='eval_usage',
                            severity='high',
                            description='使用eval函数存在安全风险',
                            file_path=file_path,
                            line_number=node.lineno,
                            code_snippet=ast.get_source_segment(content, node),
                            fix_suggestion='避免使用eval，使用安全的替代方案'
                        )
                        vulnerabilities.append(vulnerability)
                
                # 检测exec使用
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    if node.func.id == 'exec':
                        vulnerability = SecurityVulnerability(
                            vulnerability_type='exec_usage',
                            severity='high',
                            description='使用exec函数存在安全风险',
                            file_path=file_path,
                            line_number=node.lineno,
                            code_snippet=ast.get_source_segment(content, node),
                            fix_suggestion='避免使用exec，使用安全的替代方案'
                        )
                        vulnerabilities.append(vulnerability)
                        
        except SyntaxError:
            # 忽略语法错误，可能是非Python文件
            pass
        
        return vulnerabilities
    
    def audit_project(self, project_path: str) -> Dict[str, Any]:
        """审计整个项目"""
        project_path = Path(project_path)
        vulnerabilities = []
        
        # 扫描Python文件
        python_files = list(project_path.rglob('*.py'))
        
        for py_file in python_files:
            file_vulns = self.audit_file(str(py_file))
            vulnerabilities.extend(file_vulns)
        
        # 统计结果
        severity_counts = {'high': 0, 'medium': 0, 'low': 0}
        type_counts = {}
        
        for vuln in vulnerabilities:
            severity_counts[vuln.severity] += 1
            type_counts[vuln.vulnerability_type] = type_counts.get(vuln.vulnerability_type, 0) + 1
        
        return {
            'total_files': len(python_files),
            'total_vulnerabilities': len(vulnerabilities),
            'severity_counts': severity_counts,
            'type_counts': type_counts,
            'vulnerabilities': [v.to_dict() for v in vulnerabilities]
        }

class SecurityFixer:
    """安全修复器"""
    
    def __init__(self):
        self.fix_patterns = self._load_fix_patterns()
    
    def _load_fix_patterns(self) -> Dict[str, Dict]:
        """加载修复模式"""
        return {
            'sql_injection': {
                'pattern': r'(cursor\.execute\()["\'](.*?%s.*?)["\']',
                'replacement': r'\1\2',  # 占位符，实际需要更复杂的替换
                'description': '修复SQL注入漏洞'
            },
            'hardcoded_secrets': {
                'pattern': r'(password|pwd|secret|key|token)\s*=\s*["\']([^"\']{8,})["\']',
                'replacement': r'\1 = os.getenv("\1", "")',
                'description': '移除硬编码的敏感信息'
            },
            'weak_crypto': {
                'pattern': r'hashlib\.(md5|sha1)\(',
                'replacement': r'hashlib.sha256(',
                'description': '升级弱加密算法'
            }
        }
    
    def apply_fixes(self, file_path: str, vulnerabilities: List[SecurityVulnerability]) -> bool:
        """应用安全修复"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            original_content = content
            
            for vuln in vulnerabilities:
                if vuln.vulnerability_type in self.fix_patterns:
                    pattern_info = self.fix_patterns[vuln.vulnerability_type]
                    
                    # 应用修复
                    content = re.sub(pattern_info['pattern'], pattern_info['replacement'], content)
            
            # 如果内容有变化，保存文件
            if content != original_content:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"应用修复失败 {file_path}: {e}")
            return False

# 安全加固建议
SECURITY_RECOMMENDATIONS = [
    {
        'category': '认证授权',
        'recommendations': [
            '实施多因素认证',
            '使用强密码策略',
            '实现会话超时机制',
            '防止暴力破解攻击'
        ]
    },
    {
        'category': '数据保护',
        'recommendations': [
            '敏感数据加密存储',
            '实施传输加密(TLS)',
            '安全的密钥管理',
            '数据备份和恢复'
        ]
    },
    {
        'category': '输入验证',
        'recommendations': [
            '所有输入都进行验证',
            '实施输出编码',
            '防止注入攻击',
            '文件上传安全检查'
        ]
    },
    {
        'category': '错误处理',
        'recommendations': [
            '安全的错误信息',
            '详细的审计日志',
            '异常处理机制',
            '故障恢复策略'
        ]
    }
]

def perform_security_audit(project_path: str) -> Dict[str, Any]:
    """执行安全审计"""
    auditor = SecurityAuditor()
    results = auditor.audit_project(project_path)
    
    # 添加安全建议
    results['recommendations'] = SECURITY_RECOMMENDATIONS
    
    return results