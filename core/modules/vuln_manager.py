"""
漏洞管理模块 - 集成到AutoPenTest_Desktop
"""

import logging
import hashlib
from datetime import datetime
from typing import Dict, Any, Optional, List

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QPushButton, QLineEdit, QLabel, QComboBox,
    QTextEdit, QGroupBox, QFormLayout, QMessageBox,
    QFileDialog, QProgressBar
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont, QColor

from core.modules.base import ModuleBase

logger = logging.getLogger(__name__)


class VulnerabilityModule(ModuleBase):
    """漏洞管理模块"""
    
    def __init__(self):
        super().__init__("漏洞管理", "管理和跟踪发现的漏洞")
        self._vulnerabilities: List[Dict[str, Any]] = []
        self._selected_vuln: Optional[Dict[str, Any]] = None
        
    def _create_ui(self) -> QWidget:
        """创建漏洞管理UI"""
        main_widget = QWidget()
        layout = QVBoxLayout(main_widget)
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(5)
        
        # 工具栏
        toolbar_layout = QHBoxLayout()
        
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("搜索漏洞...")
        self.search_input.setStyleSheet("""
            QLineEdit {
                background-color: #3a3a3a;
                color: #ffffff;
                border: 1px solid #555555;
                border-radius: 3px;
                padding: 5px;
            }
        """)
        toolbar_layout.addWidget(self.search_input)
        
        search_btn = QPushButton("搜索")
        search_btn.clicked.connect(self._search_vulns)
        toolbar_layout.addWidget(search_btn)
        
        toolbar_layout.addSpacing(10)
        
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["全部级别", "critical", "high", "medium", "low", "info"])
        self.severity_filter.currentTextChanged.connect(self._filter_by_severity)
        toolbar_layout.addWidget(self.severity_filter)
        
        self.status_filter = QComboBox()
        self.status_filter.addItems(["全部状态", "open", "confirmed", "fixed", "ignored"])
        self.status_filter.currentTextChanged.connect(self._filter_by_status)
        toolbar_layout.addWidget(self.status_filter)
        
        toolbar_layout.addStretch()
        
        add_btn = QPushButton("+ 添加漏洞")
        add_btn.clicked.connect(self._add_vuln)
        toolbar_layout.addWidget(add_btn)
        
        update_btn = QPushButton("更新状态")
        update_btn.clicked.connect(self._update_status)
        toolbar_layout.addWidget(update_btn)
        
        delete_btn = QPushButton("删除")
        delete_btn.clicked.connect(self._delete_vuln)
        toolbar_layout.addWidget(delete_btn)
        
        export_btn = QPushButton("导出报告")
        export_btn.clicked.connect(self._export_report)
        toolbar_layout.addWidget(export_btn)
        
        layout.addLayout(toolbar_layout)
        
        # 主分割器
        splitter = QSplitter(Qt.Horizontal)
        
        # 左侧漏洞列表
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)
        
        self.vuln_table = QTableWidget()
        self.vuln_table.setColumnCount(6)
        self.vuln_table.setHorizontalHeaderLabels(["ID", "资产", "类型", "严重级别", "标题", "状态"])
        self.vuln_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.vuln_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.vuln_table.setSelectionMode(QTableWidget.SingleSelection)
        self.vuln_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.vuln_table.setAlternatingRowColors(True)
        self.vuln_table.cellClicked.connect(self._on_vuln_selected)
        self.vuln_table.setStyleSheet("""
            QTableWidget {
                background-color: #2d2d2d;
                color: #ffffff;
                gridline-color: #444444;
            }
            QTableWidget::item:selected {
                background-color: #4CAF50;
            }
            QHeaderView::section {
                background-color: #3a3a3a;
                color: #ffffff;
                padding: 5px;
                border: 1px solid #555555;
            }
        """)
        left_layout.addWidget(self.vuln_table)
        
        splitter.addWidget(left_widget)
        
        # 右侧漏洞详情
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)
        
        detail_group = QGroupBox("漏洞详情")
        detail_layout = QFormLayout()
        
        self.detail_id = QLabel("")
        self.detail_asset = QLabel("")
        self.detail_type = QLabel("")
        self.detail_severity = QLabel("")
        self.detail_title = QLabel("")
        self.detail_status = QLabel("")
        self.detail_description = QTextEdit()
        self.detail_description.setReadOnly(True)
        self.detail_description.setMaximumHeight(150)
        self.detail_evidence = QTextEdit()
        self.detail_evidence.setReadOnly(True)
        self.detail_evidence.setMaximumHeight(150)
        self.detail_created = QLabel("")
        self.detail_updated = QLabel("")
        
        detail_layout.addRow("ID:", self.detail_id)
        detail_layout.addRow("资产:", self.detail_asset)
        detail_layout.addRow("类型:", self.detail_type)
        detail_layout.addRow("严重级别:", self.detail_severity)
        detail_layout.addRow("标题:", self.detail_title)
        detail_layout.addRow("状态:", self.detail_status)
        detail_layout.addRow("描述:", self.detail_description)
        detail_layout.addRow("证据:", self.detail_evidence)
        detail_layout.addRow("创建时间:", self.detail_created)
        detail_layout.addRow("更新时间:", self.detail_updated)
        
        detail_group.setLayout(detail_layout)
        right_layout.addWidget(detail_group)
        
        # 统计信息
        stats_group = QGroupBox("漏洞统计")
        stats_layout = QVBoxLayout()
        
        self.stats_label = QLabel("")
        stats_layout.addWidget(self.stats_label)
        
        self.severity_bar = QProgressBar()
        self.severity_bar.setTextVisible(False)
        self.severity_bar.setFixedHeight(20)
        stats_layout.addWidget(self.severity_bar)
        
        stats_group.setLayout(stats_layout)
        right_layout.addWidget(stats_group)
        
        splitter.addWidget(right_widget)
        splitter.setSizes([600, 400])
        
        layout.addWidget(splitter)
        
        # 状态栏
        self.status_label = QLabel(f"共 0 个漏洞")
        layout.addWidget(self.status_label)
        
        self._load_vulns()
        
        return main_widget
    
    def _load_vulns(self):
        """加载漏洞列表"""
        try:
            from core.database.database_manager import DatabaseManager
            db = DatabaseManager()
            session = db.session
            
            from sqlalchemy import text
            result = session.execute(text("SELECT * FROM discovered_vulnerabilities ORDER BY created_at DESC"))
            rows = result.fetchall()
            
            self._vulnerabilities = [dict(row._mapping) for row in rows]
            self._refresh_table()
            self._update_stats()
            
            logger.info(f"加载了 {len(self._vulnerabilities)} 个漏洞")
        except Exception as e:
            logger.warning(f"加载漏洞失败: {e}")
            self._vulnerabilities = []
            self._refresh_table()
    
    def _refresh_table(self):
        """刷新表格显示"""
        self.vuln_table.setRowCount(len(self._vulnerabilities))
        
        for i, vuln in enumerate(self._vulnerabilities):
            self.vuln_table.setItem(i, 0, QTableWidgetItem(str(vuln.get('id', ''))))
            self.vuln_table.setItem(i, 1, QTableWidgetItem(str(vuln.get('asset_id', ''))))
            self.vuln_table.setItem(i, 2, QTableWidgetItem(str(vuln.get('type', ''))))
            self.vuln_table.setItem(i, 3, QTableWidgetItem(str(vuln.get('severity', ''))))
            self.vuln_table.setItem(i, 4, QTableWidgetItem(str(vuln.get('title', ''))))
            self.vuln_table.setItem(i, 5, QTableWidgetItem(str(vuln.get('status', ''))))
            
            # 根据严重级别设置颜色
            severity = vuln.get('severity', '').lower()
            color_map = {
                'critical': QColor("#ff0000"),
                'high': QColor("#ff6600"),
                'medium': QColor("#ffcc00"),
                'low': QColor("#00cc00"),
                'info': QColor("#0099ff")
            }
            if severity in color_map:
                item = self.vuln_table.item(i, 3)
                if item:
                    item.setForeground(color_map[severity])
        
        self.status_label.setText(f"共 {len(self._vulnerabilities)} 个漏洞")
    
    def _update_stats(self):
        """更新统计信息"""
        if not self._vulnerabilities:
            self.stats_label.setText("暂无漏洞数据")
            return
        
        severity_counts = {}
        status_counts = {}
        
        for vuln in self._vulnerabilities:
            sev = vuln.get('severity', 'unknown')
            status = vuln.get('status', 'unknown')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            status_counts[status] = status_counts.get(status, 0) + 1
        
        stats_text = "严重级别分布:\n"
        for sev in ['critical', 'high', 'medium', 'low', 'info']:
            count = severity_counts.get(sev, 0)
            if count > 0:
                stats_text += f"  {sev}: {count}\n"
        
        stats_text += "\n状态分布:\n"
        for status in ['open', 'confirmed', 'fixed', 'ignored']:
            count = status_counts.get(status, 0)
            if count > 0:
                stats_text += f"  {status}: {count}\n"
        
        self.stats_label.setText(stats_text)
    
    def _on_vuln_selected(self, row, col):
        """漏洞选择事件"""
        if 0 <= row < len(self._vulnerabilities):
            self._selected_vuln = self._vulnerabilities[row]
            self._show_vuln_detail(self._selected_vuln)
    
    def _show_vuln_detail(self, vuln: Dict[str, Any]):
        """显示漏洞详情"""
        self.detail_id.setText(str(vuln.get('id', '')))
        self.detail_asset.setText(str(vuln.get('asset_id', '')))
        self.detail_type.setText(str(vuln.get('type', '')))
        self.detail_severity.setText(str(vuln.get('severity', '')))
        self.detail_title.setText(str(vuln.get('title', '')))
        self.detail_status.setText(str(vuln.get('status', '')))
        self.detail_description.setText(str(vuln.get('description', '')))
        self.detail_evidence.setText(str(vuln.get('evidence', '')))
        self.detail_created.setText(str(vuln.get('created_at', '')))
        self.detail_updated.setText(str(vuln.get('updated_at', '')))
    
    def _add_vuln(self):
        """添加漏洞"""
        from PySide6.QtWidgets import QDialog, QDialogButtonBox
        
        dialog = QDialog(self.get_ui())
        dialog.setWindowTitle("添加漏洞")
        dialog.setMinimumWidth(500)
        
        layout = QFormLayout(dialog)
        
        asset_input = QLineEdit()
        layout.addRow("资产ID:", asset_input)
        
        type_combo = QComboBox()
        type_combo.addItems(["sqli", "xss", "csrf", "rce", "ssrf", "file_upload", "info_disclosure", "other"])
        layout.addRow("类型:", type_combo)
        
        severity_combo = QComboBox()
        severity_combo.addItems(["critical", "high", "medium", "low", "info"])
        layout.addRow("严重级别:", severity_combo)
        
        title_input = QLineEdit()
        layout.addRow("标题:", title_input)
        
        desc_input = QTextEdit()
        desc_input.setMaximumHeight(100)
        layout.addRow("描述:", desc_input)
        
        evidence_input = QTextEdit()
        evidence_input.setMaximumHeight(100)
        layout.addRow("证据:", evidence_input)
        
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addRow(buttons)
        
        if dialog.exec() == QDialog.Accepted:
            vuln_id = f"VULN_{hashlib.md5(f'{datetime.now().isoformat()}'.encode()).hexdigest()[:12]}"
            
            try:
                from core.database.database_manager import DatabaseManager
                db = DatabaseManager()
                session = db.session
                
                from sqlalchemy import text
                session.execute(text("""
                    INSERT INTO discovered_vulnerabilities (vuln_id, asset_id, vuln_type, severity, title, description, evidence, status, request_id, response_id, created_at, updated_at, meta_data)
                    VALUES (:vuln_id, :asset_id, :vuln_type, :severity, :title, :description, :evidence, :status, :request_id, :response_id, :created_at, :updated_at, :meta_data)
                """), {
                    'vuln_id': vuln_id,
                    'asset_id': asset_input.text(),
                    'vuln_type': type_combo.currentText(),
                    'severity': severity_combo.currentText(),
                    'title': title_input.text(),
                    'description': desc_input.toPlainText(),
                    'evidence': evidence_input.toPlainText(),
                    'status': 'open',
                    'request_id': '',
                    'response_id': '',
                    'created_at': datetime.now().isoformat(),
                    'updated_at': datetime.now().isoformat(),
                    'meta_data': '{}'
                })
                session.commit()
                
                self.log("INFO", f"添加漏洞: {title_input.text()}")
                self._load_vulns()
                
            except Exception as e:
                logger.error(f"添加漏洞失败: {e}")
                QMessageBox.critical(self.get_ui(), "错误", f"添加漏洞失败: {e}")
    
    def _update_status(self):
        """更新漏洞状态"""
        if not self._selected_vuln:
            QMessageBox.information(self.get_ui(), "提示", "请先选择一个漏洞")
            return
        
        from PySide6.QtWidgets import QDialog, QDialogButtonBox
        
        dialog = QDialog(self.get_ui())
        dialog.setWindowTitle("更新漏洞状态")
        
        layout = QFormLayout(dialog)
        
        status_combo = QComboBox()
        status_combo.addItems(["open", "confirmed", "fixed", "ignored"])
        status_combo.setCurrentText(self._selected_vuln.get('status', 'open'))
        layout.addRow("状态:", status_combo)
        
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addRow(buttons)
        
        if dialog.exec() == QDialog.Accepted:
            try:
                from core.database.database_manager import DatabaseManager
                db = DatabaseManager()
                session = db.session
                
                from sqlalchemy import text
                session.execute(text("""
                    UPDATE discovered_vulnerabilities SET status = :status, updated_at = :updated_at WHERE vuln_id = :vuln_id
                """), {
                    'status': status_combo.currentText(),
                    'updated_at': datetime.now().isoformat(),
                    'vuln_id': self._selected_vuln['vuln_id']
                })
                session.commit()
                
                self.log("INFO", f"更新漏洞状态: {self._selected_vuln.get('title', '')}")
                self._load_vulns()
                
            except Exception as e:
                logger.error(f"更新状态失败: {e}")
                QMessageBox.critical(self.get_ui(), "错误", f"更新状态失败: {e}")
    
    def _delete_vuln(self):
        """删除漏洞"""
        if not self._selected_vuln:
            QMessageBox.information(self.get_ui(), "提示", "请先选择一个漏洞")
            return
        
        reply = QMessageBox.question(
            self.get_ui(),
            "确认",
            f"确定要删除漏洞 '{self._selected_vuln.get('title', '')}' 吗？",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            try:
                from core.database.database_manager import DatabaseManager
                db = DatabaseManager()
                session = db.session
                
                from sqlalchemy import text
                session.execute(text("DELETE FROM discovered_vulnerabilities WHERE vuln_id = :vuln_id"), {'vuln_id': self._selected_vuln['vuln_id']})
                session.commit()
                
                self.log("INFO", f"删除漏洞: {self._selected_vuln.get('title', '')}")
                self._load_vulns()
                self._selected_vuln = None
                
            except Exception as e:
                logger.error(f"删除漏洞失败: {e}")
                QMessageBox.critical(self.get_ui(), "错误", f"删除失败: {e}")
    
    def _search_vulns(self):
        """搜索漏洞"""
        keyword = self.search_input.text().lower()
        if not keyword:
            self._load_vulns()
            return
        
        filtered = [v for v in self._vulnerabilities if keyword in str(v.get('title', '')).lower() 
                   or keyword in str(v.get('type', '')).lower()
                   or keyword in str(v.get('description', '')).lower()]
        
        self.vuln_table.setRowCount(len(filtered))
        for i, vuln in enumerate(filtered):
            self.vuln_table.setItem(i, 0, QTableWidgetItem(str(vuln.get('id', ''))))
            self.vuln_table.setItem(i, 1, QTableWidgetItem(str(vuln.get('asset_id', ''))))
            self.vuln_table.setItem(i, 2, QTableWidgetItem(str(vuln.get('type', ''))))
            self.vuln_table.setItem(i, 3, QTableWidgetItem(str(vuln.get('severity', ''))))
            self.vuln_table.setItem(i, 4, QTableWidgetItem(str(vuln.get('title', ''))))
            self.vuln_table.setItem(i, 5, QTableWidgetItem(str(vuln.get('status', ''))))
        
        self.status_label.setText(f"搜索到 {len(filtered)} 个漏洞")
    
    def _filter_by_severity(self, severity: str):
        """按严重级别过滤"""
        if severity == "全部级别":
            self._load_vulns()
            return
        
        filtered = [v for v in self._vulnerabilities if v.get('severity', '') == severity]
        self._display_filtered_vulns(filtered, f"严重级别: {severity}")
    
    def _filter_by_status(self, status: str):
        """按状态过滤"""
        if status == "全部状态":
            self._load_vulns()
            return
        
        filtered = [v for v in self._vulnerabilities if v.get('status', '') == status]
        self._display_filtered_vulns(filtered, f"状态: {status}")
    
    def _display_filtered_vulns(self, vulns: List[Dict], label: str):
        """显示过滤后的漏洞"""
        self.vuln_table.setRowCount(len(vulns))
        for i, vuln in enumerate(vulns):
            self.vuln_table.setItem(i, 0, QTableWidgetItem(str(vuln.get('id', ''))))
            self.vuln_table.setItem(i, 1, QTableWidgetItem(str(vuln.get('asset_id', ''))))
            self.vuln_table.setItem(i, 2, QTableWidgetItem(str(vuln.get('type', ''))))
            self.vuln_table.setItem(i, 3, QTableWidgetItem(str(vuln.get('severity', ''))))
            self.vuln_table.setItem(i, 4, QTableWidgetItem(str(vuln.get('title', ''))))
            self.vuln_table.setItem(i, 5, QTableWidgetItem(str(vuln.get('status', ''))))
        
        self.status_label.setText(f"{label} - {len(vulns)} 个漏洞")
    
    def _export_report(self):
        """导出漏洞报告"""
        if not self._vulnerabilities:
            QMessageBox.information(self.get_ui(), "提示", "没有可导出的漏洞")
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self.get_ui(),
            "导出漏洞报告",
            "",
            "HTML文件 (*.html);;JSON文件 (*.json)"
        )
        
        if filename:
            try:
                if filename.endswith('.json'):
                    import json
                    with open(filename, 'w', encoding='utf-8') as f:
                        json.dump(self._vulnerabilities, f, ensure_ascii=False, indent=2)
                else:
                    self._export_html_report(filename)
                
                self.log("INFO", f"导出 {len(self._vulnerabilities)} 个漏洞到 {filename}")
                QMessageBox.information(self.get_ui(), "成功", f"已导出 {len(self._vulnerabilities)} 个漏洞")
            except Exception as e:
                logger.error(f"导出报告失败: {e}")
                QMessageBox.critical(self.get_ui(), "错误", f"导出失败: {e}")
    
    def _export_html_report(self, filename: str):
        """导出HTML格式报告"""
        html = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>漏洞报告</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        h1 { color: #333; }
        table { border-collapse: collapse; width: 100%; background-color: white; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .critical { color: #ff0000; font-weight: bold; }
        .high { color: #ff6600; font-weight: bold; }
        .medium { color: #ffcc00; }
        .low { color: #00cc00; }
        .info { color: #0099ff; }
    </style>
</head>
<body>
    <h1>渗透测试漏洞报告</h1>
    <p>生成时间: """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """</p>
    <p>共发现 """ + str(len(self._vulnerabilities)) + """ 个漏洞</p>
    <table>
        <tr>
            <th>ID</th>
            <th>资产</th>
            <th>类型</th>
            <th>严重级别</th>
            <th>标题</th>
            <th>状态</th>
        </tr>
"""
        for vuln in self._vulnerabilities:
            severity = vuln.get('severity', '').lower()
            html += f"""        <tr>
            <td>{vuln.get('id', '')}</td>
            <td>{vuln.get('asset_id', '')}</td>
            <td>{vuln.get('type', '')}</td>
            <td class="{severity}">{vuln.get('severity', '')}</td>
            <td>{vuln.get('title', '')}</td>
            <td>{vuln.get('status', '')}</td>
        </tr>
"""
        
        html += """    </table>
</body>
</html>"""
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
    
    def get_status_info(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "status": self._status.name,
            "vuln_count": len(self._vulnerabilities)
        }
