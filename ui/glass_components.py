"""
玻璃拟态UI组件库 - Glassmorphism Components
基于20年UI设计经验的专业玻璃拟态效果实现
昆仑安全实验室 - 荣誉出品
"""

import logging
from PySide6.QtWidgets import (QWidget, QFrame, QVBoxLayout, QHBoxLayout, 
                               QPushButton, QLabel, QScrollArea, QGraphicsDropShadowEffect)
from PySide6.QtCore import Qt, QPropertyAnimation, QEasingCurve, QSize, QPoint
from PySide6.QtGui import QColor, QFont, QPainter, QLinearGradient, QBrush, QPainterPath, QRadialGradient

logger = logging.getLogger(__name__)

class GlassEffect:
    """玻璃拟态效果常量"""
    
    # 颜色系统
    COLORS = {
        'glass_bg': 'rgba(25, 30, 45, 0.75)',
        'glass_bg_light': 'rgba(35, 42, 63, 0.5)',
        'glass_border': 'rgba(100, 150, 255, 0.2)',
        'glass_border_light': 'rgba(100, 150, 255, 0.3)',
        'primary_blue': '#00a3ff',
        'primary_purple': '#8b5cf6',
        'primary_cyan': '#06b6d4',
        'success_green': '#10b981',
        'warning_orange': '#f59e0b',
        'error_red': '#ef4444',
        'info_blue': '#3b82f6',
        'text_primary': 'rgba(255, 255, 255, 0.95)',
        'text_secondary': 'rgba(255, 255, 255, 0.75)',
        'text_tertiary': 'rgba(255, 255, 255, 0.5)',
        'bg_ultra_dark': '#0a0e17',
        'bg_dark': '#0f1522',
        'bg_medium': '#141b2d',
        'bg_light': '#1e293b'
    }
    
    # 圆角规范
    RADIUS = {
        'small': 8,
        'medium': 12,
        'large': 16,
        'extra_large': 20
    }
    
    # 阴影规范
    SHADOWS = {
        'light': {'blur': 10, 'x': 0, 'y': 4, 'color': 'rgba(0, 0, 0, 0.2)'},
        'medium': {'blur': 20, 'x': 0, 'y': 8, 'color': 'rgba(0, 0, 0, 0.3)'},
        'heavy': {'blur': 30, 'x': 0, 'y': 12, 'color': 'rgba(0, 0, 0, 0.4)'}
    }


class GlassCard(QFrame):
    """玻璃拟态卡片组件"""
    
    def __init__(self, parent=None, radius=GlassEffect.RADIUS['large']):
        super().__init__(parent)
        self.radius = radius
        self._setup_style()
        self._setup_animation()
        
    def _setup_style(self):
        """设置玻璃拟态样式"""
        self.setStyleSheet(f"""
            GlassCard {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 rgba(25, 30, 45, 0.75),
                    stop:1 rgba(30, 38, 60, 0.65));
                border: 1px solid rgba(100, 150, 255, 0.2);
                border-radius: {self.radius}px;
            }}
        """)
        
        # 添加阴影效果
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(32)
        shadow.setXOffset(0)
        shadow.setYOffset(8)
        shadow.setColor(QColor(0, 0, 0, 100))
        self.setGraphicsEffect(shadow)
        
        self.setMinimumHeight(100)
        
    def _setup_animation(self):
        """设置悬停动画"""
        self.hover_animation = QPropertyAnimation(self, b"pos")
        self.hover_animation.setDuration(300)
        self.hover_animation.setEasingCurve(QEasingCurve.OutCubic)
        
    def enterEvent(self, event):
        """鼠标进入事件"""
        super().enterEvent(event)
        self._apply_hover_effect(True)
        
    def leaveEvent(self, event):
        """鼠标离开事件"""
        super().leaveEvent(event)
        self._apply_hover_effect(False)
        
    def _apply_hover_effect(self, hovered):
        """应用悬停效果"""
        if hovered:
            self.setStyleSheet(f"""
                GlassCard {{
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                        stop:0 rgba(30, 35, 52, 0.8),
                        stop:1 rgba(35, 43, 68, 0.7));
                    border: 1px solid rgba(100, 150, 255, 0.3);
                    border-radius: {self.radius}px;
                }}
            """)
        else:
            self._setup_style()


class GlassButton(QPushButton):
    """玻璃拟态按钮组件"""
    
    def __init__(self, text="", parent=None, button_type="primary"):
        super().__init__(text, parent)
        self.button_type = button_type
        self._setup_style()
        self._setup_font()
        
    def _setup_style(self):
        """设置按钮样式"""
        if self.button_type == "primary":
            gradient = "qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 rgba(59, 130, 246, 0.9), stop:1 rgba(139, 92, 246, 0.9))"
            shadow_color = "rgba(59, 130, 246, 0.4)"
        elif self.button_type == "success":
            gradient = "qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 rgba(16, 185, 129, 0.9), stop:1 rgba(5, 150, 105, 0.9))"
            shadow_color = "rgba(16, 185, 129, 0.4)"
        elif self.button_type == "warning":
            gradient = "qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 rgba(245, 158, 11, 0.9), stop:1 rgba(217, 119, 6, 0.9))"
            shadow_color = "rgba(245, 158, 11, 0.4)"
        elif self.button_type == "danger":
            gradient = "qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 rgba(239, 68, 68, 0.9), stop:1 rgba(220, 38, 38, 0.9))"
            shadow_color = "rgba(239, 68, 68, 0.4)"
        else:
            gradient = "qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 rgba(30, 41, 59, 0.8), stop:1 rgba(51, 65, 85, 0.7))"
            shadow_color = "rgba(0, 0, 0, 0.2)"
        
        self.setStyleSheet(f"""
            GlassButton {{
                background: {gradient};
                color: rgba(255, 255, 255, 0.95);
                border: 1px solid rgba(255, 255, 255, 0.2);
                border-radius: 12px;
                padding: 10px 20px;
                font-weight: 600;
                font-size: 14px;
            }}
            
            GlassButton:hover {{
                background: {gradient};
                border: 1px solid rgba(255, 255, 255, 0.3);
            }}
            
            GlassButton:pressed {{
                background: {gradient};
                padding: 11px 19px 9px 21px;
            }}
        """)
        
        # 添加阴影效果
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(15)
        shadow.setXOffset(0)
        shadow.setYOffset(4)
        shadow.setColor(QColor(59, 130, 246, 80) if self.button_type == "primary" else QColor(0, 0, 0, 60))
        self.setGraphicsEffect(shadow)
        
        self.setMinimumHeight(40)
        self.setMinimumWidth(100)
        self.setCursor(Qt.PointingHandCursor)
        
    def _setup_font(self):
        """设置字体"""
        font = QFont()
        font.setFamily("Segoe UI")
        font.setPixelSize(14)
        font.setWeight(QFont.DemiBold)
        self.setFont(font)


class GlassPanel(QFrame):
    """玻璃拟态面板组件 - 大型容器"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_style()
        
    def _setup_style(self):
        """设置面板样式"""
        self.setStyleSheet("""
            GlassPanel {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 rgba(20, 27, 45, 0.8),
                    stop:1 rgba(15, 21, 35, 0.7));
                border: 1px solid rgba(100, 150, 255, 0.15);
                border-radius: 20px;
            }
        """)
        
        # 添加重型阴影效果
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(50)
        shadow.setXOffset(0)
        shadow.setYOffset(25)
        shadow.setColor(QColor(0, 0, 0, 120))
        self.setGraphicsEffect(shadow)


class StatsCard(GlassCard):
    """统计数据卡片 - 带图标和数值"""
    
    def __init__(self, title="", value="", icon=None, trend=None, parent=None):
        super().__init__(parent)
        self.title = title
        self.value = value
        self.icon = icon
        self.trend = trend
        self._setup_ui()
        
    def _setup_ui(self):
        """设置统计卡片UI"""
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # 顶部区域：图标 + 标题
        top_layout = QHBoxLayout()
        
        if self.icon:
            icon_label = QLabel(self.icon)
            icon_label.setStyleSheet("font-size: 32px;")
            top_layout.addWidget(icon_label)
        
        title_label = QLabel(self.title)
        title_label.setStyleSheet(f"""
            color: {GlassEffect.COLORS['text_secondary']};
            font-size: 14px;
            font-weight: 500;
        """)
        top_layout.addWidget(title_label)
        top_layout.addStretch()
        
        layout.addLayout(top_layout)
        
        # 数值显示
        value_label = QLabel(self.value)
        value_label.setStyleSheet(f"""
            color: {GlassEffect.COLORS['text_primary']};
            font-size: 36px;
            font-weight: 700;
        """)
        layout.addWidget(value_label)
        
        # 趋势指示器
        if self.trend:
            trend_label = QLabel(self.trend)
            trend_color = GlassEffect.COLORS['success_green'] if '+' in self.trend else GlassEffect.COLORS['error_red']
            trend_label.setStyleSheet(f"""
                color: {trend_color};
                font-size: 13px;
                font-weight: 600;
            """)
            layout.addWidget(trend_label)


class GlassSectionHeader(QWidget):
    """玻璃拟态章节标题组件"""
    
    def __init__(self, title="", subtitle="", parent=None):
        super().__init__(parent)
        self.title = title
        self.subtitle = subtitle
        self._setup_ui()
        
    def _setup_ui(self):
        """设置标题UI"""
        layout = QVBoxLayout(self)
        layout.setSpacing(4)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # 主标题
        title_label = QLabel(self.title)
        title_label.setStyleSheet(f"""
            color: {GlassEffect.COLORS['text_primary']};
            font-size: 24px;
            font-weight: 700;
        """)
        layout.addWidget(title_label)
        
        # 副标题
        if self.subtitle:
            subtitle_label = QLabel(self.subtitle)
            subtitle_label.setStyleSheet(f"""
                color: {GlassEffect.COLORS['text_secondary']};
                font-size: 14px;
                font-weight: 400;
            """)
            layout.addWidget(subtitle_label)


class GlassScrollArea(QScrollArea):
    """玻璃拟态滚动区域"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_style()
        
    def _setup_style(self):
        """设置滚动区域样式"""
        self.setWidgetResizable(True)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setStyleSheet(f"""
            GlassScrollArea {{
                border: none;
                background: transparent;
            }}
            
            QScrollBar:vertical {{
                background: transparent;
                width: 8px;
                margin: 0px;
            }}
            
            QScrollBar::handle:vertical {{
                background: rgba(100, 150, 255, 0.3);
                border-radius: 4px;
                min-height: 20px;
            }}
            
            QScrollBar::handle:vertical:hover {{
                background: rgba(100, 150, 255, 0.5);
            }}
            
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
                height: 0px;
            }}
        """)


class GlassBackgroundWidget(QWidget):
    """玻璃拟态背景组件 - 带渐变和网格效果"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WA_StyledBackground, True)
        self._setup_style()
        
    def _setup_style(self):
        """设置背景样式"""
        self.setStyleSheet(f"""
            GlassBackgroundWidget {{
                background-color: {GlassEffect.COLORS['bg_ultra_dark']};
            }}
        """)
        
    def paintEvent(self, event):
        """绘制背景效果"""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        # 绘制渐变背景
        gradient = QLinearGradient(0, 0, self.width(), self.height())
        gradient.setColorAt(0, QColor(10, 14, 23))
        gradient.setColorAt(0.5, QColor(15, 21, 34))
        gradient.setColorAt(1, QColor(10, 14, 23))
        painter.fillRect(self.rect(), gradient)
        
        # 绘制网格效果
        painter.setPen(QColor(100, 150, 255, 15))
        grid_size = 40
        
        for x in range(0, self.width(), grid_size):
            painter.drawLine(x, 0, x, self.height())
            
        for y in range(0, self.height(), grid_size):
            painter.drawLine(0, y, self.width(), y)
        
        # 绘制发光效果
        center_x = self.width() // 2
        center_y = self.height() // 3
        
        glow_gradient = QRadialGradient(center_x, center_y, 300)
        glow_gradient.setColorAt(0, QColor(59, 130, 246, 30))
        glow_gradient.setColorAt(1, QColor(59, 130, 246, 0))
        painter.fillRect(self.rect(), glow_gradient)