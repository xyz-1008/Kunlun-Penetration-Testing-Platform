"""
专业级知识库阅读器组件
基于360 CNVD与字节跳动SRC安全专家经验
昆仑安全实验室 - 荣誉出品
"""

import logging
from typing import Optional, Callable
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QScrollArea, QFrame, QSplitter, QToolBar, QProgressBar,
    QMenu, QApplication, QSlider
)
from PySide6.QtCore import Qt, QUrl, Signal, QSize
from PySide6.QtGui import QIcon, QFont, QAction, QDesktopServices, QTextDocument
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWebChannel import QWebChannel

from core.knowledge.knowledge_base import KnowledgeItem, KnowledgeBase, KnowledgeRecommender

logger = logging.getLogger(__name__)


class KnowledgeReader(QWidget):
    """专业级知识库阅读器"""
    
    item_bookmarked = Signal(str)
    item_liked = Signal(str)
    item_progress_updated = Signal(str, int)
    related_item_clicked = Signal(str)
    
    def __init__(self, knowledge_base: KnowledgeBase, parent=None):
        super().__init__(parent)
        self.knowledge_base = knowledge_base
        self.recommender = KnowledgeRecommender(knowledge_base)
        self.current_item: Optional[KnowledgeItem] = None
        self.all_items: list[KnowledgeItem] = []
        self.current_index = 0
        self.font_size = 14
        self.init_ui()
        self.apply_dark_theme()
    
    def init_ui(self):
        """初始化界面"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # 顶部工具栏
        toolbar = self.create_toolbar()
        layout.addWidget(toolbar)
        
        # 主体区域（使用分割器）
        splitter = QSplitter(Qt.Horizontal)
        
        # 左侧：目录/导航（可选）
        left_panel = self.create_nav_panel()
        
        # 中间：内容区域
        center_panel = self.create_content_panel()
        
        # 右侧：相关推荐
        right_panel = self.create_recommend_panel()
        
        splitter.addWidget(left_panel)
        splitter.addWidget(center_panel)
        splitter.addWidget(right_panel)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 4)
        splitter.setStretchFactor(2, 1)
        
        layout.addWidget(splitter)
        
        # 底部状态栏
        statusbar = self.create_statusbar()
        layout.addWidget(statusbar)
    
    def create_toolbar(self) -> QToolBar:
        """创建工具栏"""
        toolbar = QToolBar("阅读器工具栏")
        toolbar.setMovable(False)
        
        # 上一篇/下一篇
        prev_action = QAction("上一篇", self)
        prev_action.setShortcut("Alt+Left")
        prev_action.triggered.connect(self.show_prev_item)
        toolbar.addAction(prev_action)
        
        next_action = QAction("下一篇", self)
        next_action.setShortcut("Alt+Right")
        next_action.triggered.connect(self.show_next_item)
        toolbar.addAction(next_action)
        
        toolbar.addSeparator()
        
        # 收藏/点赞
        self.bookmark_action = QAction("收藏", self)
        self.bookmark_action.setCheckable(True)
        self.bookmark_action.toggled.connect(self.toggle_bookmark)
        toolbar.addAction(self.bookmark_action)
        
        self.like_action = QAction("点赞", self)
        self.like_action.triggered.connect(self.like_item)
        toolbar.addAction(self.like_action)
        
        toolbar.addSeparator()
        
        # 字体大小调节
        font_dec_action = QAction("A-", self)
        font_dec_action.triggered.connect(self.decrease_font_size)
        toolbar.addAction(font_dec_action)
        
        font_inc_action = QAction("A+", self)
        font_inc_action.triggered.connect(self.increase_font_size)
        toolbar.addAction(font_inc_action)
        
        toolbar.addSeparator()
        
        # 目录
        self.toc_action = QAction("目录", self)
        self.toc_action.setCheckable(True)
        self.toc_action.setChecked(True)
        self.toc_action.toggled.connect(self.toggle_toc)
        toolbar.addAction(self.toc_action)
        
        toolbar.addSeparator()
        
        # 全屏
        fullscreen_action = QAction("全屏", self)
        fullscreen_action.setShortcut("F11")
        fullscreen_action.triggered.connect(self.toggle_fullscreen)
        toolbar.addAction(fullscreen_action)
        
        # 导出
        export_menu = QMenu("导出", self)
        export_html_action = QAction("导出为HTML", self)
        export_html_action.triggered.connect(self.export_html)
        export_menu.addAction(export_html_action)
        
        export_pdf_action = QAction("导出为PDF", self)
        export_pdf_action.triggered.connect(self.export_pdf)
        export_menu.addAction(export_pdf_action)
        
        export_action = toolbar.addAction("导出")
        export_action.setMenu(export_menu)
        
        return toolbar
    
    def create_nav_panel(self) -> QWidget:
        """创建导航面板"""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        
        # 目录标签
        toc_label = QLabel("目录")
        toc_label.setStyleSheet("font-weight: bold; font-size: 14px; padding: 8px;")
        layout.addWidget(toc_label)
        
        # 目录列表
        self.toc_scroll = QScrollArea()
        self.toc_scroll.setWidgetResizable(True)
        self.toc_widget = QWidget()
        self.toc_layout = QVBoxLayout(self.toc_widget)
        self.toc_layout.setAlignment(Qt.AlignTop)
        self.toc_scroll.setWidget(self.toc_widget)
        layout.addWidget(self.toc_scroll)
        
        self.nav_panel = panel
        return panel
    
    def create_content_panel(self) -> QWidget:
        """创建内容面板"""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        
        # 标题区域
        header_frame = QFrame()
        header_frame.setFrameShape(QFrame.StyledPanel)
        header_layout = QVBoxLayout(header_frame)
        
        self.title_label = QLabel("请选择一篇知识文章")
        self.title_label.setStyleSheet("font-size: 24px; font-weight: bold; padding: 10px;")
        self.title_label.setWordWrap(True)
        header_layout.addWidget(self.title_label)
        
        # 元信息
        meta_layout = QHBoxLayout()
        self.category_label = QLabel()
        self.category_label.setStyleSheet("color: #00bcd4;")
        meta_layout.addWidget(self.category_label)
        
        self.difficulty_label = QLabel()
        self.difficulty_label.setStyleSheet("color: #ff9800;")
        meta_layout.addWidget(self.difficulty_label)
        
        self.author_label = QLabel()
        meta_layout.addWidget(self.author_label)
        
        meta_layout.addStretch()
        
        self.views_label = QLabel()
        meta_layout.addWidget(self.views_label)
        
        self.likes_label = QLabel()
        meta_layout.addWidget(self.likes_label)
        
        header_layout.addLayout(meta_layout)
        
        # 标签
        self.tags_widget = QWidget()
        self.tags_layout = QHBoxLayout(self.tags_widget)
        self.tags_layout.setContentsMargins(0, 5, 0, 5)
        self.tags_layout.setSpacing(8)
        self.tags_layout.setAlignment(Qt.AlignLeft)
        header_layout.addWidget(self.tags_widget)
        
        layout.addWidget(header_frame)
        
        # 阅读进度条
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximumHeight(3)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                background-color: #1e1e2e;
                border: none;
            }
            QProgressBar::chunk {
                background-color: #00bcd4;
            }
        """)
        layout.addWidget(self.progress_bar)
        
        # Web内容视图
        self.web_view = QWebEngineView()
        self.web_view.setUrl(QUrl("about:blank"))
        layout.addWidget(self.web_view)
        
        return panel
    
    def create_recommend_panel(self) -> QWidget:
        """创建推荐面板"""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        
        # 相关推荐
        rec_label = QLabel("相关推荐")
        rec_label.setStyleSheet("font-weight: bold; font-size: 14px; padding: 8px;")
        layout.addWidget(rec_label)
        
        self.rec_scroll = QScrollArea()
        self.rec_scroll.setWidgetResizable(True)
        self.rec_widget = QWidget()
        self.rec_layout = QVBoxLayout(self.rec_widget)
        self.rec_layout.setAlignment(Qt.AlignTop)
        self.rec_scroll.setWidget(self.rec_widget)
        layout.addWidget(self.rec_scroll)
        
        # 热门文章
        hot_label = QLabel("热门文章")
        hot_label.setStyleSheet("font-weight: bold; font-size: 14px; padding: 8px;")
        layout.addWidget(hot_label)
        
        self.hot_scroll = QScrollArea()
        self.hot_scroll.setWidgetResizable(True)
        self.hot_widget = QWidget()
        self.hot_layout = QVBoxLayout(self.hot_widget)
        self.hot_layout.setAlignment(Qt.AlignTop)
        self.hot_scroll.setWidget(self.hot_widget)
        layout.addWidget(self.hot_scroll)
        
        return panel
    
    def create_statusbar(self) -> QWidget:
        """创建状态栏"""
        bar = QWidget()
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(8, 4, 8, 4)
        
        self.status_label = QLabel("就绪")
        layout.addWidget(self.status_label)
        
        layout.addStretch()
        
        # 字体大小显示
        self.font_size_label = QLabel(f"字号: {self.font_size}px")
        layout.addWidget(self.font_size_label)
        
        return bar
    
    def load_item(self, item_id: str):
        """加载知识条目"""
        item = self.knowledge_base.get_item(item_id)
        if not item:
            logger.warning(f"未找到知识条目: {item_id}")
            return
        
        self.current_item = item
        self.update_ui()
        self.update_toc()
        self.update_recommendations()
        self.render_content()
        
        # 更新当前索引
        if not self.all_items:
            self.all_items = self.knowledge_base.get_all_items()
        self.current_index = next((i for i, it in enumerate(self.all_items) if it.id == item.id), 0)
    
    def update_ui(self):
        """更新界面显示"""
        if not self.current_item:
            return
        
        item = self.current_item
        
        # 更新标题
        self.title_label.setText(item.title)
        
        # 更新分类和难度
        self.category_label.setText(f"【{item.category}】")
        difficulty_colors = {
            "入门": "#4caf50",
            "进阶": "#ff9800",
            "高级": "#f44336",
            "专家": "#9c27b0"
        }
        self.difficulty_label.setText(f"难度: {item.difficulty}")
        self.difficulty_label.setStyleSheet(f"color: {difficulty_colors.get(item.difficulty, '#fff')};")
        
        self.author_label.setText(f"作者: {item.author}")
        self.views_label.setText(f"阅读: {item.views}")
        self.likes_label.setText(f"点赞: {item.likes}")
        
        # 更新标签
        for i in reversed(range(self.tags_layout.count())):
            self.tags_layout.itemAt(i).widget().setParent(None)
        
        for tag in item.tags:
            tag_btn = QPushButton(tag)
            tag_btn.setStyleSheet("""
                QPushButton {
                    background-color: #313244;
                    color: #cdd6f4;
                    border: none;
                    padding: 4px 12px;
                    border-radius: 12px;
                    font-size: 12px;
                }
                QPushButton:hover {
                    background-color: #45475a;
                }
            """)
            tag_btn.clicked.connect(lambda checked, t=tag: self.search_by_tag(t))
            self.tags_layout.addWidget(tag_btn)
        
        # 更新收藏和点赞状态
        self.bookmark_action.blockSignals(True)
        self.bookmark_action.setChecked(item.bookmark)
        self.bookmark_action.blockSignals(False)
        
        # 更新进度
        self.progress_bar.setValue(item.progress)
    
    def render_content(self):
        """渲染内容"""
        if not self.current_item:
            return
        
        content = self.current_item.content
        html = self.wrap_content_html(content)
        self.web_view.setHtml(html)
    
    def wrap_content_html(self, content: str) -> str:
        """包装内容为完整HTML"""
        return f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body {{
            font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
            font-size: {self.font_size}px;
            line-height: 1.8;
            color: #cdd6f4;
            background-color: #1e1e2e;
            padding: 24px;
            max-width: 900px;
            margin: 0 auto;
        }}
        h1, h2, h3, h4, h5, h6 {{
            color: #00bcd4;
            margin-top: 2em;
            margin-bottom: 0.8em;
            font-weight: 600;
        }}
        h1 {{ font-size: 2em; }}
        h2 {{ font-size: 1.6em; border-bottom: 1px solid #313244; padding-bottom: 0.3em; }}
        h3 {{ font-size: 1.3em; }}
        p {{ margin: 1em 0; text-align: justify; }}
        ul, ol {{ margin: 1em 0; padding-left: 2em; }}
        li {{ margin: 0.5em 0; }}
        code {{
            background-color: #313244;
            padding: 0.2em 0.4em;
            border-radius: 4px;
            font-family: "Consolas", "Courier New", monospace;
        }}
        pre {{
            background-color: #181825;
            padding: 16px;
            border-radius: 8px;
            overflow-x: auto;
            border: 1px solid #313244;
        }}
        pre code {{
            background: transparent;
            padding: 0;
        }}
        blockquote {{
            border-left: 4px solid #00bcd4;
            padding-left: 16px;
            margin: 1em 0;
            color: #a6adc8;
            font-style: italic;
        }}
        a {{
            color: #00bcd4;
            text-decoration: none;
        }}
        a:hover {{
            text-decoration: underline;
        }}
        img {{
            max-width: 100%;
            height: auto;
            border-radius: 8px;
        }}
        .toc-item {{
            display: block;
            padding: 8px 12px;
            margin: 4px 0;
            border-radius: 6px;
            color: #cdd6f4;
            text-decoration: none;
            cursor: pointer;
        }}
        .toc-item:hover {{
            background-color: #313244;
        }}
    </style>
</head>
<body>
    {content}
</body>
</html>
        """
    
    def update_toc(self):
        """更新目录"""
        for i in reversed(range(self.toc_layout.count())):
            self.toc_layout.itemAt(i).widget().setParent(None)
        
        if not self.current_item:
            return
        
        # 简单的目录生成
        toc_items = [
            ("概述", 0),
            ("详细内容", 1),
        ]
        
        for title, idx in toc_items:
            btn = QPushButton(title)
            btn.setStyleSheet("""
                QPushButton {
                    text-align: left;
                    padding: 8px 12px;
                    border: none;
                    background-color: transparent;
                    color: #cdd6f4;
                    border-radius: 6px;
                }
                QPushButton:hover {
                    background-color: #313244;
                }
            """)
            btn.clicked.connect(lambda checked, i=idx: self.scroll_to_section(i))
            self.toc_layout.addWidget(btn)
    
    def update_recommendations(self):
        """更新推荐"""
        # 相关推荐
        for i in reversed(range(self.rec_layout.count())):
            self.rec_layout.itemAt(i).widget().setParent(None)
        
        if self.current_item:
            related = self.recommender.recommend_by_item(self.current_item, limit=5)
            for item in related:
                self.add_recommend_item(self.rec_layout, item)
        
        # 热门文章
        for i in reversed(range(self.hot_layout.count())):
            self.hot_layout.itemAt(i).widget().setParent(None)
        
        hot = self.knowledge_base.get_popular_items(limit=10)
        for item in hot:
            self.add_recommend_item(self.hot_layout, item)
    
    def add_recommend_item(self, layout: QVBoxLayout, item: KnowledgeItem):
        """添加推荐项"""
        btn = QPushButton()
        btn.setText(item.title)
        btn.setStyleSheet("""
            QPushButton {
                text-align: left;
                padding: 10px 12px;
                border: none;
                background-color: #313244;
                color: #cdd6f4;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #45475a;
            }
        """)
        btn.clicked.connect(lambda checked, i=item.id: self.load_item(i))
        layout.addWidget(btn)
    
    def toggle_bookmark(self, checked: bool):
        """切换收藏"""
        if not self.current_item:
            return
        self.knowledge_base.toggle_bookmark(self.current_item.id)
        self.current_item.bookmark = checked
        self.item_bookmarked.emit(self.current_item.id)
    
    def like_item(self):
        """点赞"""
        if not self.current_item:
            return
        self.knowledge_base.like_item(self.current_item.id)
        self.current_item.likes += 1
        self.likes_label.setText(f"点赞: {self.current_item.likes}")
        self.item_liked.emit(self.current_item.id)
    
    def increase_font_size(self):
        """增大字号"""
        if self.font_size < 24:
            self.font_size += 2
            self.font_size_label.setText(f"字号: {self.font_size}px")
            if self.current_item:
                self.render_content()
    
    def decrease_font_size(self):
        """减小字号"""
        if self.font_size > 10:
            self.font_size -= 2
            self.font_size_label.setText(f"字号: {self.font_size}px")
            if self.current_item:
                self.render_content()
    
    def toggle_toc(self, checked: bool):
        """显示/隐藏目录"""
        self.nav_panel.setVisible(checked)
    
    def toggle_fullscreen(self):
        """切换全屏"""
        if self.isFullScreen():
            self.showNormal()
        else:
            self.showFullScreen()
    
    def show_prev_item(self):
        """显示上一篇"""
        if not self.all_items:
            return
        if self.current_index > 0:
            self.current_index -= 1
            self.load_item(self.all_items[self.current_index].id)
    
    def show_next_item(self):
        """显示下一篇"""
        if not self.all_items:
            return
        if self.current_index < len(self.all_items) - 1:
            self.current_index += 1
            self.load_item(self.all_items[self.current_index].id)
    
    def scroll_to_section(self, idx: int):
        """滚动到指定部分"""
        # 简单实现：滚动到顶部
        self.web_view.page().runJavaScript("window.scrollTo(0, 0);")
    
    def search_by_tag(self, tag: str):
        """根据标签搜索"""
        logger.info(f"搜索标签: {tag}")
    
    def export_html(self):
        """导出为HTML"""
        logger.info("导出HTML功能开发中...")
    
    def export_pdf(self):
        """导出为PDF"""
        logger.info("导出PDF功能开发中...")
    
    def apply_dark_theme(self):
        """应用深色主题"""
        self.setStyleSheet("""
            QWidget {
                background-color: #1e1e2e;
                color: #cdd6f4;
            }
            QToolBar {
                background-color: #181825;
                border-bottom: 1px solid #313244;
                spacing: 6px;
            }
            QToolBar QToolButton {
                background-color: #313244;
                border: none;
                padding: 6px 12px;
                border-radius: 4px;
            }
            QToolBar QToolButton:hover {
                background-color: #45475a;
            }
            QScrollArea {
                border: none;
                background-color: #1e1e2e;
            }
            QFrame {
                border: none;
            }
            QSplitter::handle {
                background-color: #313244;
            }
            QSplitter::handle:hover {
                background-color: #45475a;
            }
        """)


logger.info("专业级知识库阅读器组件初始化完成")
