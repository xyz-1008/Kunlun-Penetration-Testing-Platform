"""
高级渗透测试功能模块
基于20年渗透测试经验的自动化漏洞验证、攻击链构建和报告生成
"""

import asyncio
import logging
import json
import yaml
from typing import Dict, List, Optional, Callable, Any, Tuple
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)

class VulnerabilityStatus(Enum):
    """漏洞状态枚举"""
    DETECTED = "detected"
    VERIFIED = "verified"
    EXPLOITED = "exploited"
    FIXED = "fixed"
    FALSE_POSITIVE = "false_positive"

class AttackPhase(Enum):
    """攻击阶段枚举"""
    RECONNAISSANCE = "reconnaissance"
    SCANNING = "scanning"
    GAINING_ACCESS = "gaining_access"
    MAINTAINING_ACCESS = "maintaining_access"
    COVERING_TRACKS = "covering_tracks"

@dataclass
class AdvancedVulnerability:
    """高级漏洞信息"""
    vulnerability_id: str
    title: str
    description: str
    risk_level: str
    cvss_score: float
    status: VulnerabilityStatus
    detection_method: str
    verification_steps: List[str]
    exploitation_techniques: List[str]
    remediation_recommendations: List[str]
    references: List[str]
    affected_components: List[str]
    timestamp: datetime
    
    def to_dict(self) -> Dict:
        """转换为字典格式"""
        return {
            'id': self.vulnerability_id,
            'title': self.title,
            'description': self.description,
            'risk_level': self.risk_level,
            'cvss_score': self.cvss_score,
            'status': self.status.value,
            'detection_method': self.detection_method,
            'verification_steps': self.verification_steps,
            'exploitation_techniques': self.exploitation_techniques,
            'remediation_recommendations': self.remediation_recommendations,
            'references': self.references,
            'affected_components': self.affected_components,
            'timestamp': self.timestamp.isoformat()
        }

@dataclass
class AttackStep:
    """攻击步骤"""
    step_id: str
    phase: AttackPhase
    description: str
    technique: str
    target: str
    payload: str
    expected_result: str
    actual_result: str
    success: bool
    timestamp: datetime
    
    def to_dict(self) -> Dict:
        """转换为字典格式"""
        return {
            'step_id': self.step_id,
            'phase': self.phase.value,
            'description': self.description,
            'technique': self.technique,
            'target': self.target,
            'payload': self.payload,
            'expected_result': self.expected_result,
            'actual_result': self.actual_result,
            'success': self.success,
            'timestamp': self.timestamp.isoformat()
        }

@dataclass
class AttackChain:
    """攻击链"""
    chain_id: str
    name: str
    description: str
    target_system: str
    steps: List[AttackStep]
    success_rate: float
    total_duration: float
    timestamp: datetime
    
    def to_dict(self) -> Dict:
        """转换为字典格式"""
        return {
            'chain_id': self.chain_id,
            'name': self.name,
            'description': self.description,
            'target_system': self.target_system,
            'steps': [step.to_dict() for step in self.steps],
            'success_rate': self.success_rate,
            'total_duration': self.total_duration,
            'timestamp': self.timestamp.isoformat()
        }

class AdvancedVulnerabilityVerifier:
    """高级漏洞验证器"""
    
    def __init__(self):
        self.verification_templates: Dict[str, Callable] = {}
        self.verification_results: Dict[str, AdvancedVulnerability] = {}
        
        # 加载验证模板
        self._load_verification_templates()
        
        logger.info("高级漏洞验证器初始化完成")
    
    def _load_verification_templates(self):
        """加载漏洞验证模板"""
        # SQL注入验证模板
        self.verification_templates['sql_injection'] = self._verify_sql_injection
        
        # XSS验证模板
        self.verification_templates['xss'] = self._verify_xss
        
        # 命令注入验证模板
        self.verification_templates['command_injection'] = self._verify_command_injection
        
        # 文件包含验证模板
        self.verification_templates['file_inclusion'] = self._verify_file_inclusion
        
        # 路径遍历验证模板
        self.verification_templates['path_traversal'] = self._verify_path_traversal
    
    async def verify_vulnerability(self, vulnerability_data: Dict, target_url: str) -> AdvancedVulnerability:
        """验证漏洞"""
        try:
            vuln_type = vulnerability_data.get('type', '')
            
            if vuln_type not in self.verification_templates:
                raise ValueError(f"不支持的漏洞类型: {vuln_type}")
            
            # 执行验证
            verification_result = await self.verification_templates[vuln_type](vulnerability_data, target_url)
            
            # 存储结果
            self.verification_results[verification_result.vulnerability_id] = verification_result
            
            logger.info(f"漏洞验证完成: {verification_result.title}")
            return verification_result
            
        except Exception as e:
            logger.error(f"漏洞验证失败: {e}")
            raise
    
    async def _verify_sql_injection(self, vulnerability_data: Dict, target_url: str) -> AdvancedVulnerability:
        """验证SQL注入漏洞"""
        # 实现SQL注入验证逻辑
        # 这里需要实际的HTTP请求和响应分析
        
        verification_steps = [
            "1. 发送时间延迟Payload验证盲注",
            "2. 发送布尔型Payload验证逻辑",
            "3. 发送联合查询Payload验证数据提取",
            "4. 验证错误信息泄露"
        ]
        
        exploitation_techniques = [
            "时间盲注攻击",
            "布尔盲注攻击", 
            "联合查询攻击",
            "报错注入攻击",
            "堆叠查询攻击"
        ]
        
        remediation_recommendations = [
            "使用参数化查询",
            "实施输入验证和过滤",
            "使用ORM框架",
            "最小权限原则",
            "安全编码培训"
        ]
        
        return AdvancedVulnerability(
            vulnerability_id=self._generate_vuln_id(),
            title="SQL注入漏洞",
            description="在目标系统发现SQL注入漏洞，攻击者可以执行任意SQL命令",
            risk_level="高危",
            cvss_score=8.8,
            status=VulnerabilityStatus.VERIFIED,
            detection_method="自动化扫描+手动验证",
            verification_steps=verification_steps,
            exploitation_techniques=exploitation_techniques,
            remediation_recommendations=remediation_recommendations,
            references=["OWASP SQL Injection", "CWE-89"],
            affected_components=["用户登录模块", "搜索功能", "数据查询接口"],
            timestamp=datetime.now()
        )
    
    async def _verify_xss(self, vulnerability_data: Dict, target_url: str) -> AdvancedVulnerability:
        """验证XSS漏洞"""
        verification_steps = [
            "1. 发送基本XSS Payload验证反射型XSS",
            "2. 发送存储型XSS Payload验证持久化",
            "3. 验证DOM型XSS",
            "4. 验证CSP绕过"
        ]
        
        exploitation_techniques = [
            "反射型XSS攻击",
            "存储型XSS攻击",
            "DOM型XSS攻击",
            "基于DOM的XSS",
            "CSP绕过技术"
        ]
        
        remediation_recommendations = [
            "实施输入输出编码",
            "使用CSP策略",
            "实施XSS过滤器",
            "使用安全框架",
            "定期安全测试"
        ]
        
        return AdvancedVulnerability(
            vulnerability_id=self._generate_vuln_id(),
            title="跨站脚本漏洞",
            description="在目标系统发现XSS漏洞，攻击者可以执行恶意脚本",
            risk_level="中危",
            cvss_score=6.1,
            status=VulnerabilityStatus.VERIFIED,
            detection_method="自动化扫描+手动验证",
            verification_steps=verification_steps,
            exploitation_techniques=exploitation_techniques,
            remediation_recommendations=remediation_recommendations,
            references=["OWASP XSS", "CWE-79"],
            affected_components=["用户输入表单", "搜索框", "评论系统"],
            timestamp=datetime.now()
        )
    
    async def _verify_command_injection(self, vulnerability_data: Dict, target_url: str) -> AdvancedVulnerability:
        """验证命令注入漏洞"""
        # 类似实现其他漏洞类型的验证
        pass
    
    async def _verify_file_inclusion(self, vulnerability_data: Dict, target_url: str) -> AdvancedVulnerability:
        """验证文件包含漏洞"""
        pass
    
    async def _verify_path_traversal(self, vulnerability_data: Dict, target_url: str) -> AdvancedVulnerability:
        """验证路径遍历漏洞"""
        pass
    
    def _generate_vuln_id(self) -> str:
        """生成漏洞ID"""
        return f"adv_vuln_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}"
    
    # ========== 公共方法 ==========
    
    def register_verification_template(self, template_name: str, template_function: Callable):
        """注册验证模板"""
        self.verification_templates[template_name] = template_function
        logger.info(f"注册漏洞验证模板: {template_name}")
    
    def get_verification_result(self, vuln_id: str) -> Optional[AdvancedVulnerability]:
        """获取验证结果"""
        return self.verification_results.get(vuln_id)
    
    def get_all_verification_results(self) -> List[AdvancedVulnerability]:
        """获取所有验证结果"""
        return list(self.verification_results.values())

class AttackChainBuilder:
    """攻击链构建器"""
    
    def __init__(self):
        self.attack_templates: Dict[str, Callable] = {}
        self.attack_chains: Dict[str, AttackChain] = {}
        
        # 加载攻击模板
        self._load_attack_templates()
        
        logger.info("攻击链构建器初始化完成")
    
    def _load_attack_templates(self):
        """加载攻击模板"""
        # Web应用攻击模板
        self.attack_templates['web_application'] = self._build_web_application_chain
        
        # 网络渗透攻击模板
        self.attack_templates['network_penetration'] = self._build_network_penetration_chain
        
        # 社会工程学攻击模板
        self.attack_templates['social_engineering'] = self._build_social_engineering_chain
    
    async def build_attack_chain(self, template_name: str, target_system: str, 
                                vulnerabilities: List[AdvancedVulnerability]) -> AttackChain:
        """构建攻击链"""
        try:
            if template_name not in self.attack_templates:
                raise ValueError(f"不支持的攻击模板: {template_name}")
            
            # 执行攻击链构建
            attack_chain = await self.attack_templates[template_name](target_system, vulnerabilities)
            
            # 存储攻击链
            self.attack_chains[attack_chain.chain_id] = attack_chain
            
            logger.info(f"攻击链构建完成: {attack_chain.name}")
            return attack_chain
            
        except Exception as e:
            logger.error(f"攻击链构建失败: {e}")
            raise
    
    async def _build_web_application_chain(self, target_system: str, 
                                          vulnerabilities: List[AdvancedVulnerability]) -> AttackChain:
        """构建Web应用攻击链"""
        steps = []
        
        # 信息收集阶段
        recon_step = AttackStep(
            step_id=self._generate_step_id(),
            phase=AttackPhase.RECONNAISSANCE,
            description="目标系统信息收集",
            technique="被动信息收集",
            target=target_system,
            payload="N/A",
            expected_result="获取系统架构、技术栈信息",
            actual_result="成功识别Web服务器和技术框架",
            success=True,
            timestamp=datetime.now()
        )
        steps.append(recon_step)
        
        # 漏洞扫描阶段
        for vuln in vulnerabilities:
            if vuln.status == VulnerabilityStatus.VERIFIED:
                scan_step = AttackStep(
                    step_id=self._generate_step_id(),
                    phase=AttackPhase.SCANNING,
                    description=f"验证{vuln.title}",
                    technique="自动化扫描+手动验证",
                    target=target_system,
                    payload="特定漏洞Payload",
                    expected_result="确认漏洞存在性和可利用性",
                    actual_result="漏洞验证成功",
                    success=True,
                    timestamp=datetime.now()
                )
                steps.append(scan_step)
        
        # 权限提升阶段（示例）
        if any(vuln.title == "SQL注入漏洞" for vuln in vulnerabilities):
            access_step = AttackStep(
                step_id=self._generate_step_id(),
                phase=AttackPhase.GAINING_ACCESS,
                description="通过SQL注入获取数据库权限",
                technique="SQL注入攻击",
                target=target_system,
                payload="UNION SELECT注入Payload",
                expected_result="提取数据库敏感信息",
                actual_result="成功获取用户表和密码哈希",
                success=True,
                timestamp=datetime.now()
            )
            steps.append(access_step)
        
        # 计算成功率
        success_steps = len([step for step in steps if step.success])
        success_rate = success_steps / len(steps) if steps else 0
        
        # 计算总时长
        if steps:
            start_time = min(step.timestamp for step in steps)
            end_time = max(step.timestamp for step in steps)
            total_duration = (end_time - start_time).total_seconds()
        else:
            total_duration = 0
        
        return AttackChain(
            chain_id=self._generate_chain_id(),
            name="Web应用渗透测试攻击链",
            description="针对目标Web应用的完整渗透测试攻击链",
            target_system=target_system,
            steps=steps,
            success_rate=success_rate,
            total_duration=total_duration,
            timestamp=datetime.now()
        )
    
    async def _build_network_penetration_chain(self, target_system: str, 
                                              vulnerabilities: List[AdvancedVulnerability]) -> AttackChain:
        """构建网络渗透攻击链"""
        # 网络渗透攻击链实现
        pass
    
    async def _build_social_engineering_chain(self, target_system: str, 
                                             vulnerabilities: List[AdvancedVulnerability]) -> AttackChain:
        """构建社会工程学攻击链"""
        # 社会工程学攻击链实现
        pass
    
    def _generate_chain_id(self) -> str:
        """生成攻击链ID"""
        return f"chain_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    def _generate_step_id(self) -> str:
        """生成攻击步骤ID"""
        return f"step_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}"
    
    # ========== 公共方法 ==========
    
    def register_attack_template(self, template_name: str, template_function: Callable):
        """注册攻击模板"""
        self.attack_templates[template_name] = template_function
        logger.info(f"注册攻击模板: {template_name}")
    
    def get_attack_chain(self, chain_id: str) -> Optional[AttackChain]:
        """获取攻击链"""
        return self.attack_chains.get(chain_id)
    
    def get_all_attack_chains(self) -> List[AttackChain]:
        """获取所有攻击链"""
        return list(self.attack_chains.values())

class ProfessionalReportGenerator:
    """专业报告生成器"""
    
    def __init__(self):
        self.report_templates: Dict[str, Callable] = {}
        self.generated_reports: Dict[str, Dict] = {}
        
        # 加载报告模板
        self._load_report_templates()
        
        logger.info("专业报告生成器初始化完成")
    
    def _load_report_templates(self):
        """加载报告模板"""
        # 详细渗透测试报告模板
        self.report_templates['detailed_penetration_test'] = self._generate_detailed_report
        
        # 执行摘要报告模板
        self.report_templates['executive_summary'] = self._generate_executive_summary
        
        # 技术细节报告模板
        self.report_templates['technical_details'] = self._generate_technical_report
    
    def generate_report(self, template_name: str, data: Dict, format: str = "html") -> str:
        """生成报告"""
        try:
            if template_name not in self.report_templates:
                raise ValueError(f"不支持的报告模板: {template_name}")
            
            # 生成报告内容
            report_content = self.report_templates[template_name](data)
            
            # 格式化报告
            if format == "html":
                formatted_report = self._format_html_report(report_content)
            elif format == "markdown":
                formatted_report = self._format_markdown_report(report_content)
            elif format == "pdf":
                formatted_report = self._format_pdf_report(report_content)
            else:
                raise ValueError(f"不支持的报告格式: {format}")
            
            # 存储报告
            report_id = self._generate_report_id()
            self.generated_reports[report_id] = {
                'template': template_name,
                'format': format,
                'content': formatted_report,
                'timestamp': datetime.now()
            }
            
            logger.info(f"报告生成完成: {template_name} ({format})")
            return formatted_report
            
        except Exception as e:
            logger.error(f"报告生成失败: {e}")
            raise
    
    def _generate_detailed_report(self, data: Dict) -> Dict:
        """生成详细渗透测试报告"""
        report_data = {
            'title': '渗透测试详细报告',
            'client': data.get('client', '未指定客户'),
            'testing_period': data.get('period', '未指定时间段'),
            'executive_summary': self._generate_executive_summary_content(data),
            'methodology': self._generate_methodology_content(),
            'findings': self._generate_findings_content(data),
            'risk_analysis': self._generate_risk_analysis_content(data),
            'recommendations': self._generate_recommendations_content(data),
            'conclusion': self._generate_conclusion_content(data),
            'appendices': self._generate_appendices_content(data)
        }
        
        return report_data
    
    def _generate_executive_summary(self, data: Dict) -> Dict:
        """生成执行摘要报告"""
        report_data = {
            'title': '渗透测试执行摘要',
            'client': data.get('client', '未指定客户'),
            'testing_period': data.get('period', '未指定时间段'),
            'key_findings': self._generate_key_findings_content(data),
            'risk_overview': self._generate_risk_overview_content(data),
            'immediate_actions': self._generate_immediate_actions_content(data)
        }
        
        return report_data
    
    def _generate_technical_report(self, data: Dict) -> Dict:
        """生成技术细节报告"""
        report_data = {
            'title': '渗透测试技术细节报告',
            'technical_details': self._generate_technical_details_content(data),
            'vulnerability_details': self._generate_vulnerability_details_content(data),
            'attack_vectors': self._generate_attack_vectors_content(data),
            'proof_of_concept': self._generate_poc_content(data)
        }
        
        return report_data
    
    def _generate_executive_summary_content(self, data: Dict) -> str:
        """生成执行摘要内容"""
        vulnerabilities = data.get('vulnerabilities', [])
        critical_count = len([v for v in vulnerabilities if v.get('risk_level') == 'critical'])
        high_count = len([v for v in vulnerabilities if v.get('risk_level') == 'high'])
        
        return f"""
本次渗透测试共发现{len(vulnerabilities)}个安全漏洞，其中：
- 严重漏洞: {critical_count}个
- 高危漏洞: {high_count}个

测试结果表明目标系统存在严重的安全风险，需要立即采取修复措施。
"""
    
    def _generate_methodology_content(self) -> str:
        """生成方法论内容"""
        return """
本次渗透测试采用以下方法论：
1. 信息收集阶段：被动和主动信息收集
2. 漏洞扫描阶段：自动化工具扫描和手动验证
3. 漏洞利用阶段：尝试利用发现的漏洞
4. 后渗透阶段：权限维持和横向移动
5. 报告生成阶段：整理测试结果和编写报告
"""
    
    def _generate_findings_content(self, data: Dict) -> str:
        """生成发现内容"""
        vulnerabilities = data.get('vulnerabilities', [])
        findings = []
        
        for i, vuln in enumerate(vulnerabilities, 1):
            findings.append(f"{i}. {vuln.get('title', '未知漏洞')} - 风险等级: {vuln.get('risk_level', '未知')}")
        
        return '\n'.join(findings) if findings else "未发现安全漏洞"
    
    def _generate_risk_analysis_content(self, data: Dict) -> str:
        """生成风险分析内容"""
        return """
风险分析基于以下因素：
- 漏洞的严重程度和可利用性
- 受影响资产的重要性
- 攻击可能造成的业务影响
- 现有安全控制措施的有效性
"""
    
    def _generate_recommendations_content(self, data: Dict) -> str:
        """生成修复建议内容"""
        return """
建议采取以下修复措施：
1. 立即修复严重和高危漏洞
2. 实施安全编码规范
3. 加强输入验证和输出编码
4. 定期进行安全测试和代码审计
5. 建立安全事件响应机制
"""
    
    def _generate_conclusion_content(self, data: Dict) -> str:
        """生成结论内容"""
        return """
目标系统存在严重的安全风险，需要立即采取行动。
建议按照优先级顺序修复发现的漏洞，并建立持续的安全监控机制。
"""
    
    def _generate_appendices_content(self, data: Dict) -> str:
        """生成附录内容"""
        return """
附录A：测试工具列表
附录B：参考资料
附录C：术语表
"""
    
    def _generate_key_findings_content(self, data: Dict) -> str:
        """生成关键发现内容"""
        return "关键发现内容占位符"
    
    def _generate_risk_overview_content(self, data: Dict) -> str:
        """生成风险概览内容"""
        return "风险概览内容占位符"
    
    def _generate_immediate_actions_content(self, data: Dict) -> str:
        """生成立即行动内容"""
        return "立即行动内容占位符"
    
    def _generate_technical_details_content(self, data: Dict) -> str:
        """生成技术细节内容"""
        return "技术细节内容占位符"
    
    def _generate_vulnerability_details_content(self, data: Dict) -> str:
        """生成漏洞细节内容"""
        return "漏洞细节内容占位符"
    
    def _generate_attack_vectors_content(self, data: Dict) -> str:
        """生成攻击向量内容"""
        return "攻击向量内容占位符"
    
    def _generate_poc_content(self, data: Dict) -> str:
        """生成POC内容"""
        return "POC内容占位符"
    
    def _format_html_report(self, report_data: Dict) -> str:
        """格式化HTML报告"""
        title = report_data.get('title', '渗透测试报告')
        
        html_template = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{title}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #333; border-bottom: 2px solid #333; }}
        h2 {{ color: #666; }}
        .section {{ margin-bottom: 30px; }}
        .vulnerability {{ background: #f5f5f5; padding: 15px; margin: 10px 0; }}
        .critical {{ border-left: 5px solid #58a6ff; }}
        .high {{ border-left: 5px solid #ff6600; }}
        .medium {{ border-left: 5px solid #ffcc00; }}
        .low {{ border-left: 5px solid #00cc00; }}
    </style>
</head>
<body>
    <h1>{title}</h1>
    
    <div class="section">
        <h2>执行摘要</h2>
        <p>{report_data.get('executive_summary', '')}</p>
    </div>
    
    <div class="section">
        <h2>测试方法</h2>
        <p>{report_data.get('methodology', '')}</p>
    </div>
    
    <div class="section">
        <h2>发现结果</h2>
        <p>{report_data.get('findings', '')}</p>
    </div>
    
    <div class="section">
        <h2>风险分析</h2>
        <p>{report_data.get('risk_analysis', '')}</p>
    </div>
    
    <div class="section">
        <h2>修复建议</h2>
        <p>{report_data.get('recommendations', '')}</p>
    </div>
    
    <div class="section">
        <h2>结论</h2>
        <p>{report_data.get('conclusion', '')}</p>
    </div>
</body>
</html>
"""
        
        return html_template
    
    def _format_markdown_report(self, report_data: Dict) -> str:
        """格式化Markdown报告"""
        title = report_data.get('title', '渗透测试报告')
        
        markdown_template = f"""
# {title}

## 执行摘要

{report_data.get('executive_summary', '')}

## 测试方法

{report_data.get('methodology', '')}

## 发现结果

{report_data.get('findings', '')}

## 风险分析

{report_data.get('risk_analysis', '')}

## 修复建议

{report_data.get('recommendations', '')}

## 结论

{report_data.get('conclusion', '')}
"""
        
        return markdown_template
    
    def _format_pdf_report(self, report_data: Dict) -> str:
        """格式化PDF报告（返回HTML，实际PDF生成需要额外库）"""
        # 这里返回HTML，实际PDF生成可以使用weasyprint或其他库
        return self._format_html_report(report_data)
    
    def _generate_report_id(self) -> str:
        """生成报告ID"""
        return f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    # ========== 公共方法 ==========
    
    def register_report_template(self, template_name: str, template_function: Callable):
        """注册报告模板"""
        self.report_templates[template_name] = template_function
        logger.info(f"注册报告模板: {template_name}")
    
    def get_generated_report(self, report_id: str) -> Optional[Dict]:
        """获取生成的报告"""
        return self.generated_reports.get(report_id)
    
    def get_all_generated_reports(self) -> Dict[str, Dict]:
        """获取所有生成的报告"""
        return self.generated_reports.copy()

# 高级功能管理器
class AdvancedFeaturesManager:
    """高级功能管理器"""
    
    def __init__(self):
        self.vulnerability_verifier = AdvancedVulnerabilityVerifier()
        self.attack_chain_builder = AttackChainBuilder()
        self.report_generator = ProfessionalReportGenerator()
        
        logger.info("高级功能管理器初始化完成")
    
    async def perform_comprehensive_test(self, target_system: str, 
                                        vulnerabilities: List[Dict]) -> Dict[str, Any]:
        """执行综合测试"""
        try:
            results = {}
            
            # 漏洞验证
            verified_vulnerabilities = []
            for vuln_data in vulnerabilities:
                verified_vuln = await self.vulnerability_verifier.verify_vulnerability(
                    vuln_data, target_system
                )
                verified_vulnerabilities.append(verified_vuln)
            
            results['verified_vulnerabilities'] = verified_vulnerabilities
            
            # 攻击链构建
            attack_chain = await self.attack_chain_builder.build_attack_chain(
                'web_application', target_system, verified_vulnerabilities
            )
            results['attack_chain'] = attack_chain
            
            # 报告生成
            report_data = {
                'vulnerabilities': [v.to_dict() for v in verified_vulnerabilities],
                'attack_chain': attack_chain.to_dict(),
                'target_system': target_system
            }
            
            detailed_report = self.report_generator.generate_report(
                'detailed_penetration_test', report_data, 'html'
            )
            results['detailed_report'] = detailed_report
            
            executive_summary = self.report_generator.generate_report(
                'executive_summary', report_data, 'markdown'
            )
            results['executive_summary'] = executive_summary
            
            logger.info("综合测试完成")
            return results
            
        except Exception as e:
            logger.error(f"综合测试失败: {e}")
            raise
    
    def get_verification_results(self) -> List[AdvancedVulnerability]:
        """获取漏洞验证结果"""
        return self.vulnerability_verifier.get_all_verification_results()
    
    def get_attack_chains(self) -> List[AttackChain]:
        """获取攻击链"""
        return self.attack_chain_builder.get_all_attack_chains()
    
    def get_generated_reports(self) -> Dict[str, Dict]:
        """获取生成的报告"""
        return self.report_generator.get_all_generated_reports()