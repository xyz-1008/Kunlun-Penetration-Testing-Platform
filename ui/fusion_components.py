"""
融合UI组件库 - Linear UI + 数据可视化 + 玻璃拟态
基于20年UI设计经验的专业融合设计
昆仑安全实验室 - 荣誉出品
"""

import logging
from PySide6.QtWidgets import (QWidget, QFrame, QVBoxLayout, QHBoxLayout, 
                               QPushButton, QLabel, QScrollArea, QGraphicsDropShadowEffect,
                               QTabWidget, QTabBar, QSplitter, QToolBar, QStatusBar)
from PySide6.QtCore import Qt, QPropertyAnimation, QEasingCurve, QSize, QPoint, QRectF, Signal
from PySide6.QtGui import QColor, QFont, QPainter, QLinearGradient, QBrush, QPainterPath, QRadialGradient

logger = logging.getLogger(__name__)


class FusionTheme:
    """融合主题色彩系统"""
    
    COLORS = {
        'primary': '#3b82f6',
        'secondary': '#64748b',
        'accent': '#8b5cf6',
        'success': '#10b981',
        'warning': '#f59e0b',
        'danger': '#ef4444',
        'info': '#06b6d4',
        
        'bg_elevated': 'rgba(30, 41, 59, 0.6)',
        'bg_surface': 'rgba(15, 23, 42, 0.7)',
        'bg_base': '#0f172a',
        
        'border_subtle': 'rgba(148, 163, 184, 0.15)',
        'border_medium': 'rgba(148, 163, 184, 0.25)',
        'border_strong': 'rgba(148, 163, 184, 0.4)',
        
        'text_primary': 'rgba(248, 250, 252, 0.95)',
        'text_secondary': 'rgba(148, 163, 184, 0.8)',
        'text_muted': 'rgba(148, 163, 184, 0.5)'
    }
    
    RADIUS = {
        'small': 4,
        'medium': 6,
        'large': 8
    }


class FusionCard(QFrame):
    """融合风格卡片 - Linear + 玻璃拟态"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_style()
        
    def _setup_style(self):
        self.setStyleSheet(f"""
            FusionCard {{
                background: {FusionTheme.COLORS['bg_elevated']};
                border: 1px solid {FusionTheme.COLORS['border_subtle']};
                border-radius: {FusionTheme.RADIUS['medium']}px;
            }}
        """)
        
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(8)
        shadow.setXOffset(0)
        shadow.setYOffset(2)
        shadow.setColor(QColor(0, 0, 0, 40))
        self.setGraphicsEffect(shadow)


class FusionButton(QPushButton):
    """融合风格按钮 - Linear + 玻璃拟态"""
    
    def __init__(self, text="", button_type="primary", parent=None):
        super().__init__(text, parent)
        self.button_type = button_type
        self._setup_style()
        self._setup_font()
        
    def _setup_style(self):
        bg_color = FusionTheme.COLORS['primary']
        if self.button_type == "success":
            bg_color = FusionTheme.COLORS['success']
        elif self.button_type == "warning":
            bg_color = FusionTheme.COLORS['warning']
        elif self.button_type == "danger":
            bg_color = FusionTheme.COLORS['danger']
        
        self.setStyleSheet(f"""
            FusionButton {{
                background: {bg_color};
                color: {FusionTheme.COLORS['text_primary']};
                border: none;
                border-radius: {FusionTheme.RADIUS['small']}px;
                padding: 8px 16px;
                font-weight: 500;
            }}
            
            FusionButton:hover {{
                background: {bg_color};
                opacity: 0.9;
            }}
            
            FusionButton:pressed {{
                background: {bg_color};
                opacity: 0.8;
                padding: 9px 15px 7px 17px;
            }}
        """)
        
        self.setCursor(Qt.PointingHandCursor)
        self.setMinimumHeight(32)
        
    def _setup_font(self):
        font = QFont()
        font.setFamily("Segoe UI")
        font.setPixelSize(13)
        font.setWeight(QFont.Medium)
        self.setFont(font)


class FusionSidebarItem(QFrame):
    """融合风格侧边栏项 - Linear风格"""
    
    clicked = Signal()
    
    def __init__(self, icon="", text="", parent=None):
        super().__init__(parent)
        self.icon = icon
        self.text = text
        self.is_selected = False
        self._setup_ui()
        
    def _setup_ui(self):
        layout = QHBoxLayout(self)
        layout.setSpacing(10)
        layout.setContentsMargins(12, 10, 12, 10)
        
        icon_label = QLabel(self.icon)
        icon_label.setStyleSheet("font-size: 18px;")
        
        text_label = QLabel(self.text)
        text_label.setStyleSheet(f"""
            color: {FusionTheme.COLORS['text_secondary']};
            font-size: 13px;
            font-weight: 500;
        """)
        
        layout.addWidget(icon_label)
        layout.addWidget(text_label)
        layout.addStretch()
        
        self._update_style()
        
    def set_selected(self, selected):
        self.is_selected = selected
        self._update_style()
        
    def _update_style(self):
        if self.is_selected:
            self.setStyleSheet(f"""
                FusionSidebarItem {{
                    background: rgba(59, 130, 246, 0.2);
                    border: 1px solid rgba(59, 130, 246, 0.3);
                    border-radius: {FusionTheme.RADIUS['small']}px;
                }}
            """)
        else:
            self.setStyleSheet(f"""
                FusionSidebarItem {{
                    background: transparent;
                    border: 1px solid transparent;
                    border-radius: {FusionTheme.RADIUS['small']}px;
                }}
                
                FusionSidebarItem:hover {{
                    background: rgba(148, 163, 184, 0.1);
                }}
            """)
            
    def mousePressEvent(self, event):
        self.clicked.emit()


class FusionSidebar(QFrame):
    """融合风格侧边栏 - Linear风格"""
    
    page_changed = Signal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()
        
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(4)
        layout.setContentsMargins(8, 16, 8, 16)
        
        logo_label = QLabel("🔒 昆仑安全")
        logo_label.setStyleSheet(f"""
            color: {FusionTheme.COLORS['text_primary']};
            font-size: 16px;
            font-weight: 700;
            padding: 0 8px 16px 8px;
        """)
        layout.addWidget(logo_label)
        
        self.menu_items = []
        
        menu_data = [
            ("📊", "Dashboard", "dashboard"),
            ("🌐", "Proxy", "proxy"),
            ("🔍", "Scanner", "scanner"),
            ("⚔️", "Intruder", "intruder"),
            ("🔁", "Repeater", "repeater"),
            ("🔐", "Encoder", "encoder"),
            ("📚", "Knowledge", "knowledge")
        ]
        
        for icon, text, page_id in menu_data:
            item = FusionSidebarItem(icon, text)
            item.clicked.connect(lambda checked=False, p=page_id: self._on_menu_clicked(p))
            self.menu_items.append((item, page_id))
            layout.addWidget(item)
        
        if self.menu_items:
            self.menu_items[0][0].set_selected(True)
        
        layout.addStretch()
        
        self.setStyleSheet(f"""
            FusionSidebar {{
                background: {FusionTheme.COLORS['bg_surface']};
                border-right: 1px solid {FusionTheme.COLORS['border_subtle']};
            }}
        """)
        self.setMinimumWidth(200)
        self.setMaximumWidth(240)
        
    def _on_menu_clicked(self, page_id):
        for item, pid in self.menu_items:
            item.set_selected(pid == page_id)
        self.page_changed.emit(page_id)


class FusionTabWidget(QTabWidget):
    """融合风格标签页 - Linear风格"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_style()
        
    def _setup_style(self):
        self.setStyleSheet(f"""
            QTabWidget::pane {{
                border: 1px solid {FusionTheme.COLORS['border_subtle']};
                background: {FusionTheme.COLORS['bg_surface']};
                border-radius: {FusionTheme.RADIUS['small']}px;
            }}
            
            QTabBar::tab {{
                background: transparent;
                color: {FusionTheme.COLORS['text_secondary']};
                padding: 8px 16px;
                margin-right: 2px;
                border: none;
                border-bottom: 2px solid transparent;
            }}
            
            QTabBar::tab:selected {{
                color: {FusionTheme.COLORS['text_primary']};
                border-bottom: 2px solid {FusionTheme.COLORS['primary']};
            }}
            
            QTabBar::tab:hover:!selected {{
                color: {FusionTheme.COLORS['text_primary']};
                background: rgba(148, 163, 184, 0.1);
            }}
        """)


class FusionStatsCard(QFrame):
    """融合风格统计卡片 - 数据可视化 + 玻璃拟态"""
    
    def __init__(self, title="", value="", icon="", trend=None, parent=None):
        super().__init__(parent)
        self.title = title
        self.value = value
        self.icon = icon
        self.trend = trend
        self._setup_ui()
        
    def _setup_ui(self):
        self.setStyleSheet(f"""
            FusionStatsCard {{
                background: {FusionTheme.COLORS['bg_elevated']};
                border: 1px solid {FusionTheme.COLORS['border_subtle']};
                border-radius: {FusionTheme.RADIUS['medium']}px;
            }}
        """)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(8)
        layout.setContentsMargins(16, 12, 16, 12)
        
        top_layout = QHBoxLayout()
        
        if self.icon:
            icon_label = QLabel(self.icon)
            icon_label.setStyleSheet("font-size: 24px;")
            top_layout.addWidget(icon_label)
        
        title_label = QLabel(self.title)
        title_label.setStyleSheet(f"""
            color: {FusionTheme.COLORS['text_secondary']};
            font-size: 12px;
            font-weight: 500;
        """)
        top_layout.addWidget(title_label)
        top_layout.addStretch()
        
        layout.addLayout(top_layout)
        
        value_label = QLabel(self.value)
        value_label.setStyleSheet(f"""
            color: {FusionTheme.COLORS['text_primary']};
            font-size: 24px;
            font-weight: 700;
        """)
        layout.addWidget(value_label)
        
        if self.trend:
            trend_label = QLabel(self.trend)
            trend_color = FusionTheme.COLORS['success'] if '+' in self.trend else FusionTheme.COLORS['danger']
            trend_label.setStyleSheet(f"""
                color: {trend_color};
                font-size: 11px;
                font-weight: 600;
            """)
            layout.addWidget(trend_label)


class FusionBackgroundWidget(QWidget):
    """融合风格背景 - Linear风格"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WA_StyledBackground, True)
        self._setup_style()
        
    def _setup_style(self):
        self.setStyleSheet(f"""
            FusionBackgroundWidget {{
                background-color: {FusionTheme.COLORS['bg_base']};
            }}
        """)