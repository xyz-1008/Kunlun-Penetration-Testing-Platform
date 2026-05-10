"""
专业级UI组件库
基于20年UI设计经验
昆仑安全实验室 - 荣誉出品
"""

import logging
from PySide6.QtWidgets import (QWidget, QFrame, QVBoxLayout, QHBoxLayout, 
                               QPushButton, QLabel, QScrollArea, QGraphicsDropShadowEffect)
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont

logger = logging.getLogger(__name__)


class ProfTheme:
    """专业级主题色彩系统"""
    
    COLORS = {
        'primary': '#2563eb',
        'secondary': '#64748b',
        'accent': '#7c3aed',
        'success': '#059669',
        'warning': '#d97706',
        'danger': '#dc2626',
        'info': '#0891b2',
        
        'bg_elevated': '#1e293b',
        'bg_surface': '#0f172a',
        'bg_base': '#020617',
        
        'border_subtle': 'rgba(148, 163, 184, 0.15)',
        'border_medium': 'rgba(148, 163, 184, 0.35)',
        'border_strong': 'rgba(148, 163, 184, 0.6)',
        
        'text_primary': 'rgba(248, 250, 252, 0.98)',
        'text_secondary': 'rgba(148, 163, 184, 0.85)',
        'text_muted': 'rgba(148, 163, 184, 0.55)'
    }
    
    RADIUS = {
        'small': 4,
        'medium': 6,
        'large': 8
    }


class ProfCard(QFrame):
    """专业级卡片组件"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_style()
        
    def _setup_style(self):
        self.setStyleSheet(f"""
            ProfCard {{
                background: {ProfTheme.COLORS['bg_elevated']};
                border: 1px solid {ProfTheme.COLORS['border_medium']};
                border-radius: {ProfTheme.RADIUS['medium']}px;
            }}
        """)
        
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(12)
        shadow.setXOffset(0)
        shadow.setYOffset(4)
        shadow.setColor(QColor(0, 0, 0, 50))
        self.setGraphicsEffect(shadow)


class ProfButton(QPushButton):
    """专业级按钮组件"""
    
    def __init__(self, text="", button_type="primary", parent=None):
        super().__init__(text, parent)
        self.button_type = button_type
        self._setup_style()
        self._setup_font()
        
    def _setup_style(self):
        bg_color = ProfTheme.COLORS['primary']
        if self.button_type == "success":
            bg_color = ProfTheme.COLORS['success']
        elif self.button_type == "warning":
            bg_color = ProfTheme.COLORS['warning']
        elif self.button_type == "danger":
            bg_color = ProfTheme.COLORS['danger']
        elif self.button_type == "secondary":
            bg_color = ProfTheme.COLORS['secondary']
        
        self.setStyleSheet(f"""
            ProfButton {{
                background: {bg_color};
                color: {ProfTheme.COLORS['text_primary']};
                border: none;
                border-radius: {ProfTheme.RADIUS['small']}px;
                padding: 8px 16px;
                font-weight: 600;
            }}
            
            ProfButton:hover {{
                background: {bg_color};
                opacity: 0.9;
            }}
            
            ProfButton:pressed {{
                background: {bg_color};
                opacity: 0.8;
            }}
        """)
        
        self.setCursor(Qt.PointingHandCursor)
        self.setMinimumHeight(36)
        
    def _setup_font(self):
        font = QFont()
        font.setFamily("Segoe UI")
        font.setPixelSize(13)
        font.setWeight(QFont.DemiBold)
        self.setFont(font)


class ProfStatsCard(QFrame):
    """专业级统计卡片组件"""
    
    def __init__(self, title="", value="", icon="", trend=None, accent_color=None, parent=None):
        super().__init__(parent)
        self.title = title
        self.value = value
        self.icon = icon
        self.trend = trend
        self.accent_color = accent_color or ProfTheme.COLORS['primary']
        self._setup_ui()
        
    def _setup_ui(self):
        self.setStyleSheet(f"""
            ProfStatsCard {{
                background: {ProfTheme.COLORS['bg_elevated']};
                border: 1px solid {ProfTheme.COLORS['border_medium']};
                border-left: 3px solid {self.accent_color};
                border-radius: {ProfTheme.RADIUS['medium']}px;
            }}
        """)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(8)
        layout.setContentsMargins(20, 16, 20, 16)
        
        top_layout = QHBoxLayout()
        
        if self.icon:
            icon_label = QLabel(self.icon)
            icon_label.setStyleSheet("font-size: 28px;")
            top_layout.addWidget(icon_label)
        
        title_label = QLabel(self.title)
        title_label.setStyleSheet(f"""
            color: {ProfTheme.COLORS['text_secondary']};
            font-size: 13px;
            font-weight: 600;
        """)
        top_layout.addWidget(title_label)
        top_layout.addStretch()
        
        layout.addLayout(top_layout)
        
        value_label = QLabel(self.value)
        value_label.setStyleSheet(f"""
            color: {ProfTheme.COLORS['text_primary']};
            font-size: 28px;
            font-weight: 700;
        """)
        layout.addWidget(value_label)
        
        if self.trend:
            trend_label = QLabel(self.trend)
            trend_color = ProfTheme.COLORS['success'] if '+' in self.trend else ProfTheme.COLORS['danger']
            trend_label.setStyleSheet(f"""
                color: {trend_color};
                font-size: 12px;
                font-weight: 700;
            """)
            layout.addWidget(trend_label)


class ProfBackgroundWidget(QWidget):
    """专业级背景组件"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WA_StyledBackground, True)
        self._setup_style()
        
    def _setup_style(self):
        self.setStyleSheet(f"""
            ProfBackgroundWidget {{
                background-color: {ProfTheme.COLORS['bg_base']};
            }}
        """)