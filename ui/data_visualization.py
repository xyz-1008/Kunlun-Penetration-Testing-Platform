"""
数据可视化组件库 - Data Visualization Components
基于20年UI设计经验的专业数据可视化实现
昆仑安全实验室 - 荣誉出品
"""

import logging
import random
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, 
                               QLabel, QFrame, QGridLayout)
from PySide6.QtCore import Qt, QTimer, QRectF, QPointF
from PySide6.QtGui import (QPainter, QColor, QFont, QLinearGradient, 
                          QRadialGradient, QConicalGradient, QPainterPath, QBrush)
from .glass_components import GlassEffect

logger = logging.getLogger(__name__)


class CircularProgressWidget(QWidget):
    """环形进度组件 - 用于漏洞扫描进度展示"""
    
    def __init__(self, value=0, max_value=100, parent=None):
        super().__init__(parent)
        self.value = value
        self.max_value = max_value
        self.setMinimumSize(120, 120)
        self.setMaximumSize(200, 200)
        
    def set_value(self, value):
        self.value = min(value, self.max_value)
        self.update()
        
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        center_x = self.width() // 2
        center_y = self.height() // 2
        radius = min(center_x, center_y) - 10
        
        # 绘制背景圆环
        bg_path = QPainterPath()
        bg_path.addEllipse(QPointF(center_x, center_y), radius, radius)
        
        bg_gradient = QConicalGradient(center_x, center_y, 90)
        bg_gradient.setColorAt(0, QColor(30, 41, 59, 100))
        bg_gradient.setColorAt(1, QColor(15, 23, 42, 100))
        
        painter.setPen(Qt.NoPen)
        painter.setBrush(QBrush(bg_gradient))
        painter.drawPath(bg_path)
        
        # 绘制进度圆环
        progress = self.value / self.max_value
        start_angle = 90 * 16
        span_angle = -int(progress * 360 * 16)
        
        progress_path = QPainterPath()
        progress_path.arcMoveTo(center_x - radius, center_y - radius, 
                                radius * 2, radius * 2, 90)
        progress_path.arcTo(center_x - radius, center_y - radius, 
                           radius * 2, radius * 2, 90, -progress * 360)
        
        progress_gradient = QConicalGradient(center_x, center_y, 90)
        progress_gradient.setColorAt(0, QColor(59, 130, 246))
        progress_gradient.setColorAt(0.5, QColor(139, 92, 246))
        progress_gradient.setColorAt(1, QColor(6, 182, 212))
        
        pen = painter.pen()
        pen.setWidth(8)
        pen.setCapStyle(Qt.RoundCap)
        pen.setBrush(QBrush(progress_gradient))
        painter.setPen(pen)
        painter.setBrush(Qt.NoBrush)
        painter.drawArc(center_x - radius, center_y - radius, 
                       radius * 2, radius * 2, start_angle, span_angle)
        
        # 绘制内部圆环
        inner_radius = radius - 20
        inner_path = QPainterPath()
        inner_path.addEllipse(QPointF(center_x, center_y), inner_radius, inner_radius)
        
        inner_gradient = QRadialGradient(center_x, center_y, inner_radius)
        inner_gradient.setColorAt(0, QColor(20, 27, 45, 200))
        inner_gradient.setColorAt(1, QColor(15, 21, 35, 200))
        
        painter.setPen(Qt.NoPen)
        painter.setBrush(QBrush(inner_gradient))
        painter.drawPath(inner_path)
        
        # 绘制数值
        painter.setPen(QColor(GlassEffect.COLORS['text_primary']))
        font = QFont()
        font.setFamily("Segoe UI")
        font.setPixelSize(28)
        font.setWeight(QFont.Bold)
        painter.setFont(font)
        
        text = f"{int(self.value)}%"
        text_rect = QRectF(0, 0, self.width(), self.height())
        painter.drawText(text_rect, Qt.AlignCenter, text)


class BarChartWidget(QWidget):
    """柱状图组件 - 用于漏洞类型统计"""
    
    def __init__(self, data=None, parent=None):
        super().__init__(parent)
        self.data = data or [
            ("SQL注入", 45),
            ("XSS", 32),
            ("CSRF", 18),
            ("文件上传", 25),
            ("命令注入", 15)
        ]
        self.setMinimumHeight(200)
        
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        padding = 40
        chart_width = self.width() - padding * 2
        chart_height = self.height() - padding * 2
        
        # 绘制坐标轴
        painter.setPen(QColor(100, 150, 255, 50))
        painter.drawLine(padding, self.height() - padding, 
                        self.width() - padding, self.height() - padding)
        painter.drawLine(padding, padding, padding, self.height() - padding)
        
        # 计算柱子宽度
        bar_count = len(self.data)
        bar_width = (chart_width - (bar_count - 1) * 10) // bar_count
        
        max_value = max(item[1] for item in self.data)
        
        for i, (label, value) in enumerate(self.data):
            x = padding + i * (bar_width + 10)
            bar_height = (value / max_value) * chart_height
            y = self.height() - padding - bar_height
            
            # 绘制柱子渐变
            gradient = QLinearGradient(x, y, x, self.height() - padding)
            
            if i == 0:
                gradient.setColorAt(0, QColor(59, 130, 246, 200))
                gradient.setColorAt(1, QColor(59, 130, 246, 100))
            elif i == 1:
                gradient.setColorAt(0, QColor(139, 92, 246, 200))
                gradient.setColorAt(1, QColor(139, 92, 246, 100))
            elif i == 2:
                gradient.setColorAt(0, QColor(16, 185, 129, 200))
                gradient.setColorAt(1, QColor(16, 185, 129, 100))
            else:
                gradient.setColorAt(0, QColor(245, 158, 11, 200))
                gradient.setColorAt(1, QColor(245, 158, 11, 100))
            
            painter.setPen(Qt.NoPen)
            painter.setBrush(QBrush(gradient))
            
            bar_rect = QRectF(x, y, bar_width, bar_height)
            painter.drawRoundedRect(bar_rect, 6, 6)
            
            # 绘制标签
            painter.setPen(QColor(GlassEffect.COLORS['text_secondary']))
            font = QFont()
            font.setFamily("Segoe UI")
            font.setPixelSize(11)
            painter.setFont(font)
            
            label_rect = QRectF(x, self.height() - padding + 5, bar_width, 20)
            painter.drawText(label_rect, Qt.AlignCenter, label)
            
            # 绘制数值
            painter.setPen(QColor(GlassEffect.COLORS['text_primary']))
            font.setPixelSize(12)
            font.setWeight(QFont.Bold)
            painter.setFont(font)
            
            value_rect = QRectF(x, y - 25, bar_width, 20)
            painter.drawText(value_rect, Qt.AlignCenter, str(value))


class RiskIndicatorWidget(QWidget):
    """风险指示器组件 - 实时显示当前风险等级"""
    
    def __init__(self, risk_level="medium", parent=None):
        super().__init__(parent)
        self.risk_level = risk_level
        self.setMinimumSize(80, 80)
        
    def set_risk_level(self, level):
        self.risk_level = level
        self.update()
        
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        center_x = self.width() // 2
        center_y = self.height() // 2
        radius = min(center_x, center_y) - 5
        
        # 确定风险颜色
        risk_colors = {
            'low': (QColor(16, 185, 129), "低"),
            'medium': (QColor(245, 158, 11), "中"),
            'high': (QColor(239, 68, 68), "高"),
            'critical': (QColor(220, 38, 38), "紧急")
        }
        
        color, label = risk_colors.get(self.risk_level, risk_colors['medium'])
        
        # 绘制外圈发光效果
        glow_gradient = QRadialGradient(center_x, center_y, radius)
        glow_gradient.setColorAt(0, QColor(color.red(), color.green(), color.blue(), 100))
        glow_gradient.setColorAt(0.7, QColor(color.red(), color.green(), color.blue(), 30))
        glow_gradient.setColorAt(1, QColor(color.red(), color.green(), color.blue(), 0))
        
        painter.setPen(Qt.NoPen)
        painter.setBrush(QBrush(glow_gradient))
        painter.drawEllipse(QPointF(center_x, center_y), radius + 10, radius + 10)
        
        # 绘制主圆
        main_gradient = QRadialGradient(center_x - radius/3, center_y - radius/3, radius)
        main_gradient.setColorAt(0, color.lighter(120))
        main_gradient.setColorAt(1, color.darker(120))
        
        painter.setBrush(QBrush(main_gradient))
        painter.drawEllipse(QPointF(center_x, center_y), radius, radius)
        
        # 绘制标签
        painter.setPen(QColor(255, 255, 255))
        font = QFont()
        font.setFamily("Segoe UI")
        font.setPixelSize(16)
        font.setWeight(QFont.Bold)
        painter.setFont(font)
        
        text_rect = QRectF(0, 0, self.width(), self.height())
        painter.drawText(text_rect, Qt.AlignCenter, label)


class LiveStatsWidget(QWidget):
    """实时统计面板 - 显示当前活动状态"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()
        self._start_animation()
        
    def _setup_ui(self):
        layout = QHBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # 扫描中计数
        self.scanning_count = self._create_stat_item("🔍", "扫描中", "3")
        layout.addWidget(self.scanning_count)
        
        # 已发现漏洞
        self.vulns_found = self._create_stat_item("⚠️", "已发现", "12")
        layout.addWidget(self.vulns_found)
        
        # 已完成任务
        self.tasks_done = self._create_stat_item("✅", "已完成", "47")
        layout.addWidget(self.tasks_done)
        
        # 系统状态
        self.system_status = self._create_stat_item("🟢", "系统状态", "正常")
        layout.addWidget(self.system_status)
        
    def _create_stat_item(self, icon, label, value):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(4)
        layout.setContentsMargins(12, 8, 12, 8)
        
        icon_label = QLabel(icon)
        icon_label.setAlignment(Qt.AlignCenter)
        icon_label.setStyleSheet("font-size: 24px;")
        
        value_label = QLabel(value)
        value_label.setAlignment(Qt.AlignCenter)
        value_label.setStyleSheet(f"""
            color: {GlassEffect.COLORS['text_primary']};
            font-size: 20px;
            font-weight: 700;
        """)
        
        label_text = QLabel(label)
        label_text.setAlignment(Qt.AlignCenter)
        label_text.setStyleSheet(f"""
            color: {GlassEffect.COLORS['text_secondary']};
            font-size: 12px;
        """)
        
        layout.addWidget(icon_label)
        layout.addWidget(value_label)
        layout.addWidget(label_text)
        
        widget.setStyleSheet(f"""
            background: rgba(25, 30, 45, 0.5);
            border: 1px solid rgba(100, 150, 255, 0.15);
            border-radius: 12px;
        """)
        
        return widget
        
    def _start_animation(self):
        """启动数值动画效果"""
        self.timer = QTimer()
        self.timer.timeout.connect(self._update_stats)
        self.timer.start(3000)
        
    def _update_stats(self):
        """更新统计数值"""
        if hasattr(self, 'vulns_found'):
            # 模拟漏洞计数更新
            current = random.randint(10, 25)
            value_label = self.vulns_found.findChild(QLabel, "")
            if value_label and value_label.text().isdigit():
                value_label.setText(str(current))


class DataVisualizationPanel(QWidget):
    """数据可视化主面板"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()
        
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(20)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # 实时统计面板
        self.live_stats = LiveStatsWidget()
        layout.addWidget(self.live_stats)
        
        # 图表区域
        charts_layout = QHBoxLayout()
        charts_layout.setSpacing(20)
        
        # 左侧：环形进度
        progress_widget = QWidget()
        progress_layout = QVBoxLayout(progress_widget)
        
        progress_title = QLabel("扫描进度")
        progress_title.setStyleSheet(f"""
            color: {GlassEffect.COLORS['text_primary']};
            font-size: 16px;
            font-weight: 600;
            padding-bottom: 10px;
        """)
        progress_layout.addWidget(progress_title)
        
        self.circular_progress = CircularProgressWidget(value=67)
        progress_layout.addWidget(self.circular_progress, 0, Qt.AlignCenter)
        
        charts_layout.addWidget(progress_widget, stretch=1)
        
        # 右侧：柱状图
        chart_widget = QWidget()
        chart_layout = QVBoxLayout(chart_widget)
        
        chart_title = QLabel("漏洞类型分布")
        chart_title.setStyleSheet(f"""
            color: {GlassEffect.COLORS['text_primary']};
            font-size: 16px;
            font-weight: 600;
            padding-bottom: 10px;
        """)
        chart_layout.addWidget(chart_title)
        
        self.bar_chart = BarChartWidget()
        chart_layout.addWidget(self.bar_chart)
        
        charts_layout.addWidget(chart_widget, stretch=2)
        
        layout.addLayout(charts_layout)
        
        # 风险指示器
        risk_layout = QHBoxLayout()
        
        risk_title = QLabel("当前风险等级")
        risk_title.setStyleSheet(f"""
            color: {GlassEffect.COLORS['text_primary']};
            font-size: 16px;
            font-weight: 600;
        """)
        risk_layout.addWidget(risk_title)
        
        risk_layout.addStretch()
        
        self.risk_indicator = RiskIndicatorWidget(risk_level="high")
        risk_layout.addWidget(self.risk_indicator)
        
        layout.addLayout(risk_layout)