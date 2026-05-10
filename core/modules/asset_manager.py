"""
资产管理模块 - 集成到AutoPenTest_Desktop
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
    QFileDialog, QToolBar, QStatusBar
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QAction, QFont

from core.modules.base import ModuleBase

logger = logging.getLogger(__name__)


class AssetModule(ModuleBase):
    """资产管理模块"""
    
    def __init__(self):
        super().__init__("资产管理", "管理渗透测试目标资产信息")
        self._assets: List[Dict[str, Any]] = []
        self._selected_asset: Optional[Dict[str, Any]] = None
        
    def _create_ui(self) -> QWidget:
        """创建资产管理UI"""
        main_widget = QWidget()
        layout = QVBoxLayout(main_widget)
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(5)
        
        # 工具栏
        toolbar_layout = QHBoxLayout()
        
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("搜索资产...")
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
        search_btn.clicked.connect(self._search_assets)
        toolbar_layout.addWidget(search_btn)
        
        toolbar_layout.addSpacing(10)
        
        self.type_filter = QComboBox()
        self.type_filter.addItems(["全部类型", "Web应用", "API接口", "服务器", "数据库", "移动应用", "其他"])
        self.type_filter.currentTextChanged.connect(self._filter_by_type)
        toolbar_layout.addWidget(self.type_filter)
        
        toolbar_layout.addStretch()
        
        add_btn = QPushButton("+ 添加资产")
        add_btn.clicked.connect(self._add_asset)
        toolbar_layout.addWidget(add_btn)
        
        edit_btn = QPushButton("编辑")
        edit_btn.clicked.connect(self._edit_asset)
        toolbar_layout.addWidget(edit_btn)
        
        delete_btn = QPushButton("删除")
        delete_btn.clicked.connect(self._delete_asset)
        toolbar_layout.addWidget(delete_btn)
        
        export_btn = QPushButton("导出")
        export_btn.clicked.connect(self._export_assets)
        toolbar_layout.addWidget(export_btn)
        
        layout.addLayout(toolbar_layout)
        
        # 主分割器
        splitter = QSplitter(Qt.Horizontal)
        
        # 左侧资产列表
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)
        
        self.asset_table = QTableWidget()
        self.asset_table.setColumnCount(6)
        self.asset_table.setHorizontalHeaderLabels(["资产ID", "类型", "名称", "目标", "状态", "创建时间"])
        self.asset_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.asset_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.asset_table.setSelectionMode(QTableWidget.SingleSelection)
        self.asset_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.asset_table.setAlternatingRowColors(True)
        self.asset_table.cellClicked.connect(self._on_asset_selected)
        self.asset_table.setStyleSheet("""
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
        left_layout.addWidget(self.asset_table)
        
        splitter.addWidget(left_widget)
        
        # 右侧资产详情
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)
        
        detail_group = QGroupBox("资产详情")
        detail_layout = QFormLayout()
        
        self.detail_id = QLabel("")
        self.detail_type = QLabel("")
        self.detail_name = QLabel("")
        self.detail_target = QLabel("")
        self.detail_status = QLabel("")
        self.detail_description = QTextEdit()
        self.detail_description.setReadOnly(True)
        self.detail_description.setMaximumHeight(100)
        self.detail_created = QLabel("")
        self.detail_updated = QLabel("")
        
        detail_layout.addRow("资产ID:", self.detail_id)
        detail_layout.addRow("类型:", self.detail_type)
        detail_layout.addRow("名称:", self.detail_name)
        detail_layout.addRow("目标:", self.detail_target)
        detail_layout.addRow("状态:", self.detail_status)
        detail_layout.addRow("描述:", self.detail_description)
        detail_layout.addRow("创建时间:", self.detail_created)
        detail_layout.addRow("更新时间:", self.detail_updated)
        
        detail_group.setLayout(detail_layout)
        right_layout.addWidget(detail_group)
        
        splitter.addWidget(right_widget)
        splitter.setSizes([600, 400])
        
        layout.addWidget(splitter)
        
        # 状态栏
        self.status_label = QLabel(f"共 0 个资产")
        layout.addWidget(self.status_label)
        
        self._load_assets()
        
        return main_widget
    
    def _load_assets(self):
        """加载资产列表"""
        try:
            from core.database.database_manager import DatabaseManager
            db = DatabaseManager()
            session = db.session
            
            from sqlalchemy import text
            result = session.execute(text("SELECT * FROM assets ORDER BY created_at DESC"))
            rows = result.fetchall()
            
            self._assets = [dict(row._mapping) for row in rows]
            self._refresh_table()
            
            logger.info(f"加载了 {len(self._assets)} 个资产")
        except Exception as e:
            logger.warning(f"加载资产失败: {e}")
            self._assets = []
            self._refresh_table()
    
    def _refresh_table(self):
        """刷新表格显示"""
        self.asset_table.setRowCount(len(self._assets))
        
        for i, asset in enumerate(self._assets):
            self.asset_table.setItem(i, 0, QTableWidgetItem(str(asset.get('asset_id', ''))))
            self.asset_table.setItem(i, 1, QTableWidgetItem(str(asset.get('asset_type', ''))))
            self.asset_table.setItem(i, 2, QTableWidgetItem(str(asset.get('target', ''))))
            self.asset_table.setItem(i, 3, QTableWidgetItem(str(asset.get('description', ''))))
            self.asset_table.setItem(i, 4, QTableWidgetItem(str(asset.get('status', ''))))
            self.asset_table.setItem(i, 5, QTableWidgetItem(str(asset.get('created_at', ''))))
            self.asset_table.setItem(i, 6, QTableWidgetItem(str(asset.get('updated_at', ''))))
        
        self.status_label.setText(f"共 {len(self._assets)} 个资产")
    
    def _on_asset_selected(self, row, col):
        """资产选择事件"""
        if 0 <= row < len(self._assets):
            self._selected_asset = self._assets[row]
            self._show_asset_detail(self._selected_asset)
    
    def _show_asset_detail(self, asset: Dict[str, Any]):
        """显示资产详情"""
        self.detail_id.setText(str(asset.get('asset_id', '')))
        self.detail_type.setText(str(asset.get('asset_type', '')))
        self.detail_name.setText(str(asset.get('name', '')))
        self.detail_target.setText(str(asset.get('target', '')))
        self.detail_status.setText(str(asset.get('status', '')))
        self.detail_description.setText(str(asset.get('description', '')))
        self.detail_created.setText(str(asset.get('created_at', '')))
        self.detail_updated.setText(str(asset.get('updated_at', '')))
    
    def _add_asset(self):
        """添加资产"""
        from PySide6.QtWidgets import QDialog, QDialogButtonBox
        
        dialog = QDialog(self.get_ui())
        dialog.setWindowTitle("添加资产")
        dialog.setMinimumWidth(500)
        
        layout = QFormLayout(dialog)
        
        type_combo = QComboBox()
        type_combo.addItems(["Web应用", "API接口", "服务器", "数据库", "移动应用", "其他"])
        layout.addRow("类型:", type_combo)
        
        name_input = QLineEdit()
        layout.addRow("名称:", name_input)
        
        target_input = QLineEdit()
        layout.addRow("目标(URL/IP):", target_input)
        
        desc_input = QTextEdit()
        desc_input.setMaximumHeight(80)
        layout.addRow("描述:", desc_input)
        
        tags_input = QLineEdit()
        layout.addRow("标签:", tags_input)
        
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addRow(buttons)
        
        if dialog.exec() == QDialog.Accepted:
            asset_id = f"ASSET_{hashlib.md5(f'{datetime.now().isoformat()}'.encode()).hexdigest()[:12]}"
            
            try:
                from core.database.database_manager import DatabaseManager
                db = DatabaseManager()
                session = db.session
                
                from sqlalchemy import text
                session.execute(text("""
                    INSERT INTO assets (asset_id, name, asset_type, target, description, status, tags, meta_data, created_at, updated_at)
                    VALUES (:asset_id, :name, :asset_type, :target, :description, :status, :tags, :meta_data, :created_at, :updated_at)
                """), {
                    'asset_id': asset_id,
                    'name': name_input.text(),
                    'asset_type': type_combo.currentText(),
                    'target': target_input.text(),
                    'description': desc_input.toPlainText(),
                    'status': 'active',
                    'tags': tags_input.text(),
                    'meta_data': '{}',
                    'created_at': datetime.now().isoformat(),
                    'updated_at': datetime.now().isoformat()
                })
                session.commit()
                
                self.log("INFO", f"添加资产: {name_input.text()}")
                self._load_assets()
                
            except Exception as e:
                logger.error(f"添加资产失败: {e}")
                QMessageBox.critical(self.get_ui(), "错误", f"添加资产失败: {e}")
    
    def _edit_asset(self):
        """编辑资产"""
        if not self._selected_asset:
            QMessageBox.information(self.get_ui(), "提示", "请先选择一个资产")
            return
        
        QMessageBox.information(self.get_ui(), "提示", "编辑功能开发中...")
    
    def _delete_asset(self):
        """删除资产"""
        if not self._selected_asset:
            QMessageBox.information(self.get_ui(), "提示", "请先选择一个资产")
            return
        
        reply = QMessageBox.question(
            self.get_ui(),
            "确认",
            f"确定要删除资产 '{self._selected_asset.get('name', '')}' 吗？",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            try:
                from core.database.database_manager import DatabaseManager
                db = DatabaseManager()
                session = db.session
                
                from sqlalchemy import text
                session.execute(text("DELETE FROM assets WHERE asset_id = :asset_id"), {'asset_id': self._selected_asset['asset_id']})
                session.commit()
                
                self.log("INFO", f"删除资产: {self._selected_asset.get('name', '')}")
                self._load_assets()
                self._selected_asset = None
                
            except Exception as e:
                logger.error(f"删除资产失败: {e}")
                QMessageBox.critical(self.get_ui(), "错误", f"删除资产失败: {e}")
    
    def _search_assets(self):
        """搜索资产"""
        keyword = self.search_input.text().lower()
        if not keyword:
            self._load_assets()
            return
        
        filtered = [a for a in self._assets if keyword in str(a.get('name', '')).lower() 
                   or keyword in str(a.get('target', '')).lower()
                   or keyword in str(a.get('description', '')).lower()]
        
        self.asset_table.setRowCount(len(filtered))
        for i, asset in enumerate(filtered):
            self.asset_table.setItem(i, 0, QTableWidgetItem(str(asset.get('asset_id', ''))))
            self.asset_table.setItem(i, 1, QTableWidgetItem(str(asset.get('asset_type', ''))))
            self.asset_table.setItem(i, 2, QTableWidgetItem(str(asset.get('name', ''))))
            self.asset_table.setItem(i, 3, QTableWidgetItem(str(asset.get('target', ''))))
            self.asset_table.setItem(i, 4, QTableWidgetItem(str(asset.get('status', ''))))
            self.asset_table.setItem(i, 5, QTableWidgetItem(str(asset.get('created_at', '')[:19])))
        
        self.status_label.setText(f"搜索到 {len(filtered)} 个资产")
    
    def _filter_by_type(self, type_name: str):
        """按类型过滤"""
        if type_name == "全部类型":
            self._load_assets()
            return
        
        filtered = [a for a in self._assets if a.get('type', '') == type_name]
        
        self.asset_table.setRowCount(len(filtered))
        for i, asset in enumerate(filtered):
            self.asset_table.setItem(i, 0, QTableWidgetItem(str(asset.get('id', ''))))
            self.asset_table.setItem(i, 1, QTableWidgetItem(str(asset.get('type', ''))))
            self.asset_table.setItem(i, 2, QTableWidgetItem(str(asset.get('name', ''))))
            self.asset_table.setItem(i, 3, QTableWidgetItem(str(asset.get('url', ''))))
            self.asset_table.setItem(i, 4, QTableWidgetItem(str(asset.get('ip', ''))))
            self.asset_table.setItem(i, 5, QTableWidgetItem(str(asset.get('port', ''))))
            self.asset_table.setItem(i, 6, QTableWidgetItem(str(asset.get('status', ''))))
        
        self.status_label.setText(f"过滤到 {len(filtered)} 个资产")
    
    def _export_assets(self):
        """导出资产"""
        if not self._assets:
            QMessageBox.information(self.get_ui(), "提示", "没有可导出的资产")
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self.get_ui(),
            "导出资产",
            "",
            "JSON文件 (*.json);;CSV文件 (*.csv)"
        )
        
        if filename:
            try:
                import json
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(self._assets, f, ensure_ascii=False, indent=2)
                
                self.log("INFO", f"导出 {len(self._assets)} 个资产到 {filename}")
                QMessageBox.information(self.get_ui(), "成功", f"已导出 {len(self._assets)} 个资产")
            except Exception as e:
                logger.error(f"导出资产失败: {e}")
                QMessageBox.critical(self.get_ui(), "错误", f"导出失败: {e}")
    
    def get_status_info(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "status": self._status.name,
            "asset_count": len(self._assets)
        }
