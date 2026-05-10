"""
报告生成系统模块
"""

import os
import sys
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class ReportFormat(Enum):
    """报告格式"""
    HTML = "html"
    PDF = "pdf"
    MARKDOWN = "markdown"
    JSON = "json"
    EXCEL = "excel"


class SeverityLevel(Enum):
    """严重程度"""
    CRITICAL = "严重"
    HIGH = "高危"
    MEDIUM = "中危"
    LOW = "低危"
    INFO = "信息"


@dataclass
class VulnerabilityDetail:
    """漏洞详情"""
    name: str
    cve: str = ""
    cvss: float = 0.0
    severity: SeverityLevel = SeverityLevel.INFO
    description: str = ""
    affected_asset: str = ""
    reproduction_steps: List[str] = field(default_factory=list)
    payload: str = ""
    response_evidence: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    discovered_at: datetime = field(default_factory=datetime.now)


@dataclass
class AssetSummary:
    """资产摘要"""
    target: str
    product: str = ""
    version: str = ""
    ports: List[int] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    vulnerabilities: List[VulnerabilityDetail] = field(default_factory=list)


@dataclass
class ScanReport:
    """扫描报告"""
    report_id: str
    title: str
    scan_start_time: datetime
    scan_end_time: datetime
    duration_seconds: float
    total_assets: int
    total_vulnerabilities: int
    severity_counts: Dict[str, int] = field(default_factory=dict)
    assets: List[AssetSummary] = field(default_factory=list)
    vulnerabilities: List[VulnerabilityDetail] = field(default_factory=list)
    summary: str = ""
    recommendations: List[str] = field(default_factory=list)


class ReportGenerator:
    """报告生成器"""
    
    def __init__(self, template_dir: str = None):
        self.template_dir = Path(template_dir) if template_dir else Path(__file__).parent.parent.parent / "templates" / "reports"
        self.template_dir.mkdir(parents=True, exist_ok=True)
        self._templates: Dict[str, str] = {}
        self._load_templates()
    
    def _load_templates(self):
        """加载模板"""
        if not self.template_dir.exists():
            return
        
        for template_file in self.template_dir.glob("*.html"):
            with open(template_file, "r", encoding="utf-8") as f:
                self._templates[template_file.stem] = f.read()
    
    def generate_report(self, report: ScanReport, format: ReportFormat = ReportFormat.HTML) -> str:
        """生成报告"""
        if format == ReportFormat.HTML:
            return self._generate_html_report(report)
        elif format == ReportFormat.JSON:
            return self._generate_json_report(report)
        elif format == ReportFormat.MARKDOWN:
            return self._generate_markdown_report(report)
        else:
            return self._generate_html_report(report)
    
    def _generate_html_report(self, report: ScanReport) -> str:
        """生成HTML报告"""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{report.title}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 2px solid #4CAF50; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .summary {{ background: #e8f5e9; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .summary-item {{ display: inline-block; margin: 10px 20px; text-align: center; }}
        .summary-number {{ font-size: 2em; font-weight: bold; color: #4CAF50; }}
        .summary-label {{ color: #666; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #4CAF50; color: white; }}
        tr:hover {{ background: #f5f5f5; }}
        .severity-critical {{ background: #ffebee; color: #c62828; padding: 4px 8px; border-radius: 4px; }}
        .severity-high {{ background: #fff3e0; color: #ef6c00; padding: 4px 8px; border-radius: 4px; }}
        .severity-medium {{ background: #fff9c4; color: #f57f17; padding: 4px 8px; border-radius: 4px; }}
        .severity-low {{ background: #e8f5e9; color: #2e7d32; padding: 4px 8px; border-radius: 4px; }}
        .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; text-align: center; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{report.title}</h1>
        
        <div class="summary">
            <h2>扫描概览</h2>
            <div class="summary-item">
                <div class="summary-number">{report.total_assets}</div>
                <div class="summary-label">资产总数</div>
            </div>
            <div class="summary-item">
                <div class="summary-number">{report.total_vulnerabilities}</div>
                <div class="summary-label">漏洞总数</div>
            </div>
            <div class="summary-item">
                <div class="summary-number">{report.severity_counts.get('严重', 0)}</div>
                <div class="summary-label">严重漏洞</div>
            </div>
            <div class="summary-item">
                <div class="summary-number">{report.severity_counts.get('高危', 0)}</div>
                <div class="summary-label">高危漏洞</div>
            </div>
        </div>
        
        <h2>资产清单</h2>
        <table>
            <tr>
                <th>目标</th>
                <th>产品</th>
                <th>版本</th>
                <th>端口</th>
                <th>漏洞数</th>
            </tr>
"""
        
        for asset in report.assets:
            ports_str = ", ".join(str(p) for p in asset.ports[:5])
            html += f"""
            <tr>
                <td>{asset.target}</td>
                <td>{asset.product}</td>
                <td>{asset.version}</td>
                <td>{ports_str}</td>
                <td>{len(asset.vulnerabilities)}</td>
            </tr>
"""
        
        html += """
        </table>
        
        <h2>漏洞详情</h2>
        <table>
            <tr>
                <th>漏洞名称</th>
                <th>CVE</th>
                <th>CVSS</th>
                <th>严重程度</th>
                <th>影响资产</th>
            </tr>
"""
        
        for vuln in report.vulnerabilities:
            severity_class = f"severity-{vuln.severity.value.lower()}"
            html += f"""
            <tr>
                <td>{vuln.name}</td>
                <td>{vuln.cve}</td>
                <td>{vuln.cvss}</td>
                <td><span class="{severity_class}">{vuln.severity.value}</span></td>
                <td>{vuln.affected_asset}</td>
            </tr>
"""
        
        html += f"""
        </table>
        
        <h2>修复建议</h2>
        <ul>
"""
        
        for rec in report.recommendations:
            html += f"<li>{rec}</li>\n"
        
        html += f"""
        </ul>
        
        <div class="footer">
            <p>报告生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>扫描持续时间: {report.duration_seconds:.2f} 秒</p>
        </div>
    </div>
</body>
</html>
"""
        
        return html
    
    def _generate_json_report(self, report: ScanReport) -> str:
        """生成JSON报告"""
        report_dict = {
            "report_id": report.report_id,
            "title": report.title,
            "scan_start_time": report.scan_start_time.isoformat(),
            "scan_end_time": report.scan_end_time.isoformat(),
            "duration_seconds": report.duration_seconds,
            "total_assets": report.total_assets,
            "total_vulnerabilities": report.total_vulnerabilities,
            "severity_counts": report.severity_counts,
            "summary": report.summary,
            "recommendations": report.recommendations,
            "assets": [
                {
                    "target": a.target,
                    "product": a.product,
                    "version": a.version,
                    "ports": a.ports,
                    "services": a.services,
                    "vulnerabilities": [
                        {
                            "name": v.name,
                            "cve": v.cve,
                            "cvss": v.cvss,
                            "severity": v.severity.value,
                            "description": v.description,
                            "affected_asset": v.affected_asset,
                            "reproduction_steps": v.reproduction_steps,
                            "payload": v.payload,
                            "response_evidence": v.response_evidence,
                            "remediation": v.remediation,
                            "references": v.references,
                            "discovered_at": v.discovered_at.isoformat()
                        }
                        for v in a.vulnerabilities
                    ]
                }
                for a in report.assets
            ]
        }
        
        return json.dumps(report_dict, indent=2, ensure_ascii=False)
    
    def _generate_markdown_report(self, report: ScanReport) -> str:
        """生成Markdown报告"""
        md = f"# {report.title}\n\n"
        md += f"## 扫描概览\n\n"
        md += f"- **资产总数**: {report.total_assets}\n"
        md += f"- **漏洞总数**: {report.total_vulnerabilities}\n"
        md += f"- **严重漏洞**: {report.severity_counts.get('严重', 0)}\n"
        md += f"- **高危漏洞**: {report.severity_counts.get('高危', 0)}\n"
        md += f"- **扫描持续时间**: {report.duration_seconds:.2f} 秒\n\n"
        
        md += "## 资产清单\n\n"
        md += "| 目标 | 产品 | 版本 | 端口 | 漏洞数 |\n"
        md += "|------|------|------|------|--------|\n"
        
        for asset in report.assets:
            ports_str = ", ".join(str(p) for p in asset.ports[:5])
            md += f"| {asset.target} | {asset.product} | {asset.version} | {ports_str} | {len(asset.vulnerabilities)} |\n"
        
        md += "\n## 漏洞详情\n\n"
        
        for vuln in report.vulnerabilities:
            md += f"### {vuln.name}\n\n"
            md += f"- **CVE**: {vuln.cve}\n"
            md += f"- **CVSS**: {vuln.cvss}\n"
            md += f"- **严重程度**: {vuln.severity.value}\n"
            md += f"- **影响资产**: {vuln.affected_asset}\n"
            md += f"- **描述**: {vuln.description}\n\n"
            
            if vuln.reproduction_steps:
                md += "**复现步骤**:\n\n"
                for i, step in enumerate(vuln.reproduction_steps, 1):
                    md += f"{i}. {step}\n"
                md += "\n"
            
            if vuln.remediation:
                md += f"**修复建议**: {vuln.remediation}\n\n"
        
        md += "## 修复建议\n\n"
        for rec in report.recommendations:
            md += f"- {rec}\n"
        
        return md
    
    def save_report(self, report: ScanReport, output_path: str, format: ReportFormat = ReportFormat.HTML):
        """保存报告"""
        content = self.generate_report(report, format)
        
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        
        logger.info(f"报告已保存: {output_path}")
        return output_path
    
    def get_ui(self):
        """获取报告模块UI"""
        from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QFormLayout, QComboBox, QLineEdit, QPushButton, QTextEdit, QTableWidget, QTableWidgetItem, QHeaderView, QLabel, QFileDialog, QMessageBox
        from PySide6.QtCore import Qt
        
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        config_group = QGroupBox("报告配置")
        config_layout = QFormLayout(config_group)
        
        self.report_title_input = QLineEdit("渗透测试报告")
        config_layout.addRow("报告标题:", self.report_title_input)
        
        self.report_format_combo = QComboBox()
        self.report_format_combo.addItems(["HTML", "JSON", "Markdown"])
        config_layout.addRow("报告格式:", self.report_format_combo)
        
        self.output_path_input = QLineEdit()
        self.output_path_input.setPlaceholderText("选择输出路径...")
        output_layout = QHBoxLayout()
        output_layout.addWidget(self.output_path_input)
        browse_btn = QPushButton("浏览")
        browse_btn.clicked.connect(self._browse_output_path)
        output_layout.addWidget(browse_btn)
        config_layout.addRow("输出路径:", output_layout)
        
        layout.addWidget(config_group)
        
        btn_layout = QHBoxLayout()
        generate_btn = QPushButton("生成报告")
        generate_btn.clicked.connect(self._generate_report_ui)
        btn_layout.addWidget(generate_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)
        
        self.report_preview = QTextEdit()
        self.report_preview.setReadOnly(True)
        self.report_preview.setPlaceholderText("报告预览将显示在这里...")
        layout.addWidget(self.report_preview)
        
        return widget
    
    def _browse_output_path(self):
        """浏览输出路径"""
        from PySide6.QtWidgets import QFileDialog
        filename, _ = QFileDialog.getSaveFileName(None, "保存报告", "", "HTML Files (*.html);;JSON Files (*.json);;Markdown Files (*.md)")
        if filename:
            self.output_path_input.setText(filename)
    
    def _generate_report_ui(self):
        """生成报告"""
        from PySide6.QtWidgets import QMessageBox
        title = self.report_title_input.text() or "渗透测试报告"
        output_path = self.output_path_input.text()
        
        if not output_path:
            QMessageBox.warning(None, "警告", "请指定输出路径")
            return
        
        format_map = {"HTML": ReportFormat.HTML, "JSON": ReportFormat.JSON, "Markdown": ReportFormat.MARKDOWN}
        fmt = format_map.get(self.report_format_combo.currentText(), ReportFormat.HTML)
        
        report = ScanReport(
            report_id="auto",
            title=title,
            scan_start_time=datetime.now(),
            scan_end_time=datetime.now(),
            duration_seconds=0,
            total_assets=0,
            total_vulnerabilities=0,
            severity_counts={},
            summary="自动生成报告",
            recommendations=["建议定期扫描", "及时修复高危漏洞"]
        )
        
        try:
            self.save_report(report, output_path, fmt)
            self.report_preview.setText(f"报告已生成: {output_path}\n\n格式: {fmt.value}\n标题: {title}")
            QMessageBox.information(None, "成功", f"报告已生成: {output_path}")
        except Exception as e:
            QMessageBox.critical(None, "错误", f"生成报告失败: {str(e)}")
