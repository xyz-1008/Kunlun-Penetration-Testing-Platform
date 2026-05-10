"""
国际化多语言支持模块
昆仑安全实验室 - 专业级安全测试平台
支持中文、英文、日文等多种语言
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class I18nManager:
    """国际化管理器"""
    
    def __init__(self, locale_dir: Optional[str] = None):
        self.current_language = "zh_CN"
        self.translations: Dict[str, Dict[str, str]] = {}
        self.locale_dir = Path(locale_dir) if locale_dir else Path(__file__).parent.parent / "locales"
        self.supported_languages = {
            "zh_CN": "简体中文",
            "zh_TW": "繁體中文",
            "en_US": "English",
            "ja_JP": "日本語",
            "ko_KR": "한국어",
            "de_DE": "Deutsch",
            "fr_FR": "Français",
            "es_ES": "Español"
        }
        
        self._init_locales()
        
    def _init_locales(self):
        """初始化本地化目录"""
        try:
            self.locale_dir.mkdir(exist_ok=True)
            self._create_default_translations()
            self.load_translations()
        except Exception as e:
            logger.error(f"初始化国际化系统失败: {e}")
            
    def _create_default_translations(self):
        """创建默认翻译文件"""
        
        # 简体中文翻译
        zh_cn = {
            "app_name": "昆仑安全测试平台 Pro",
            "app_description": "专业级综合安全测试平台",
            "menu_file": "文件",
            "menu_new_project": "新建项目",
            "menu_open_project": "打开项目",
            "menu_save_project": "保存项目",
            "menu_exit": "退出",
            "menu_edit": "编辑",
            "menu_undo": "撤销",
            "menu_redo": "重做",
            "menu_view": "视图",
            "menu_tools": "工具",
            "menu_help": "帮助",
            "menu_about": "关于",
            "menu_user_manual": "用户手册",
            "tab_proxy": "代理",
            "tab_scanner": "扫描器",
            "tab_intruder": "入侵者",
            "tab_decoder": "编码器",
            "tab_repeater": "重放器",
            "tab_comparer": "比较器",
            "tab_extender": "扩展",
            "btn_start": "开始",
            "btn_stop": "停止",
            "btn_clear": "清空",
            "btn_save": "保存",
            "btn_load": "加载",
            "btn_send": "发送",
            "btn_reset": "重置",
            "status_ready": "就绪",
            "status_loading": "加载中...",
            "status_scanning": "扫描中...",
            "status_attacking": "攻击中...",
            "status_complete": "完成",
            "status_error": "错误",
            "dialog_title_warning": "警告",
            "dialog_title_error": "错误",
            "dialog_title_info": "信息",
            "dialog_title_confirm": "确认",
            "msg_confirm_exit": "确定要退出应用吗？",
            "msg_confirm_clear": "确定要清空所有数据吗？",
            "msg_save_success": "保存成功",
            "msg_save_failed": "保存失败",
            "msg_load_success": "加载成功",
            "msg_load_failed": "加载失败",
            "language": "语言",
            "theme": "主题",
            "dark_theme": "深色主题",
            "light_theme": "浅色主题",
            "settings": "设置",
            "preferences": "首选项",
            "about_text": "昆仑安全测试平台 Pro\n\n版本: 1.0.0\n\n基于20年渗透测试经验和360网络安全标准\n昆仑安全实验室 荣誉出品",
            "welcome": "欢迎使用昆仑安全测试平台 Pro",
            "project_name": "项目名称",
            "target_url": "目标URL",
            "scan_results": "扫描结果",
            "vulnerability_found": "发现漏洞",
            "severity_high": "高危",
            "severity_medium": "中危",
            "severity_low": "低危",
            "severity_info": "信息",
            "request": "请求",
            "response": "响应",
            "history": "历史",
            "payload": "Payload",
            "attack_mode": "攻击模式",
            "sniper": "狙击手",
            "battering_ram": "攻城锤",
            "pitchfork": "草叉",
            "cluster_bomb": "集束炸弹",
            "encoding": "编码",
            "decoding": "解码",
            "url_encode": "URL编码",
            "url_decode": "URL解码",
            "base64_encode": "Base64编码",
            "base64_decode": "Base64解码",
            "hex_encode": "Hex编码",
            "hex_decode": "Hex解码",
            "html_encode": "HTML编码",
            "html_decode": "HTML解码",
            "md5_hash": "MD5哈希",
            "sha1_hash": "SHA1哈希",
            "sha256_hash": "SHA256哈希"
        }
        
        # 英文翻译
        en_us = {
            "app_name": "Kunlun Security Testing Platform Pro",
            "app_description": "Professional Integrated Security Testing Platform",
            "menu_file": "File",
            "menu_new_project": "New Project",
            "menu_open_project": "Open Project",
            "menu_save_project": "Save Project",
            "menu_exit": "Exit",
            "menu_edit": "Edit",
            "menu_undo": "Undo",
            "menu_redo": "Redo",
            "menu_view": "View",
            "menu_tools": "Tools",
            "menu_help": "Help",
            "menu_about": "About",
            "menu_user_manual": "User Manual",
            "tab_proxy": "Proxy",
            "tab_scanner": "Scanner",
            "tab_intruder": "Intruder",
            "tab_decoder": "Decoder",
            "tab_repeater": "Repeater",
            "tab_comparer": "Comparer",
            "tab_extender": "Extender",
            "btn_start": "Start",
            "btn_stop": "Stop",
            "btn_clear": "Clear",
            "btn_save": "Save",
            "btn_load": "Load",
            "btn_send": "Send",
            "btn_reset": "Reset",
            "status_ready": "Ready",
            "status_loading": "Loading...",
            "status_scanning": "Scanning...",
            "status_attacking": "Attacking...",
            "status_complete": "Complete",
            "status_error": "Error",
            "dialog_title_warning": "Warning",
            "dialog_title_error": "Error",
            "dialog_title_info": "Information",
            "dialog_title_confirm": "Confirm",
            "msg_confirm_exit": "Are you sure you want to exit?",
            "msg_confirm_clear": "Are you sure you want to clear all data?",
            "msg_save_success": "Save successful",
            "msg_save_failed": "Save failed",
            "msg_load_success": "Load successful",
            "msg_load_failed": "Load failed",
            "language": "Language",
            "theme": "Theme",
            "dark_theme": "Dark Theme",
            "light_theme": "Light Theme",
            "settings": "Settings",
            "preferences": "Preferences",
            "about_text": "Kunlun Security Testing Platform Pro\n\nVersion: 1.0.0\n\nBased on 20 years of penetration testing experience and 360 cybersecurity standards\nKunlun Security Laboratory",
            "welcome": "Welcome to Kunlun Security Testing Platform Pro",
            "project_name": "Project Name",
            "target_url": "Target URL",
            "scan_results": "Scan Results",
            "vulnerability_found": "Vulnerability Found",
            "severity_high": "High",
            "severity_medium": "Medium",
            "severity_low": "Low",
            "severity_info": "Info",
            "request": "Request",
            "response": "Response",
            "history": "History",
            "payload": "Payload",
            "attack_mode": "Attack Mode",
            "sniper": "Sniper",
            "battering_ram": "Battering Ram",
            "pitchfork": "Pitchfork",
            "cluster_bomb": "Cluster Bomb",
            "encoding": "Encoding",
            "decoding": "Decoding",
            "url_encode": "URL Encode",
            "url_decode": "URL Decode",
            "base64_encode": "Base64 Encode",
            "base64_decode": "Base64 Decode",
            "hex_encode": "Hex Encode",
            "hex_decode": "Hex Decode",
            "html_encode": "HTML Encode",
            "html_decode": "HTML Decode",
            "md5_hash": "MD5 Hash",
            "sha1_hash": "SHA1 Hash",
            "sha256_hash": "SHA256 Hash"
        }
        
        # 日文翻译
        ja_jp = {
            "app_name": "崑崙セキュリティテストプラットフォーム Pro",
            "app_description": "プロフェッショナル統合セキュリティテストプラットフォーム",
            "menu_file": "ファイル",
            "menu_new_project": "新規プロジェクト",
            "menu_open_project": "プロジェクトを開く",
            "menu_save_project": "プロジェクトを保存",
            "menu_exit": "終了",
            "menu_edit": "編集",
            "menu_undo": "元に戻す",
            "menu_redo": "やり直し",
            "menu_view": "表示",
            "menu_tools": "ツール",
            "menu_help": "ヘルプ",
            "menu_about": "について",
            "menu_user_manual": "ユーザーマニュアル",
            "tab_proxy": "プロキシ",
            "tab_scanner": "スキャナー",
            "tab_intruder": "イントルーダー",
            "tab_decoder": "デコーダー",
            "tab_repeater": "リピーター",
            "tab_comparer": "コンパレーター",
            "tab_extender": "エクステンダー",
            "btn_start": "開始",
            "btn_stop": "停止",
            "btn_clear": "クリア",
            "btn_save": "保存",
            "btn_load": "読み込み",
            "btn_send": "送信",
            "btn_reset": "リセット",
            "status_ready": "準備完了",
            "status_loading": "読み込み中...",
            "status_scanning": "スキャン中...",
            "status_attacking": "攻撃中...",
            "status_complete": "完了",
            "status_error": "エラー",
            "dialog_title_warning": "警告",
            "dialog_title_error": "エラー",
            "dialog_title_info": "情報",
            "dialog_title_confirm": "確認",
            "msg_confirm_exit": "アプリケーションを終了しますか？",
            "msg_confirm_clear": "すべてのデータをクリアしますか？",
            "msg_save_success": "保存完了",
            "msg_save_failed": "保存失敗",
            "msg_load_success": "読み込み完了",
            "msg_load_failed": "読み込み失敗",
            "language": "言語",
            "theme": "テーマ",
            "dark_theme": "ダークテーマ",
            "light_theme": "ライトテーマ",
            "settings": "設定",
            "preferences": "環境設定",
            "about_text": "崑崙セキュリティテストプラットフォーム Pro\n\nバージョン: 1.0.0\n\n20年のペネトレーションテスト経験と360サイバーセキュリティ基準に基づく\n崑崙セキュリティ研究所",
            "welcome": "崑崙セキュリティテストプラットフォーム Pro へようこそ",
            "project_name": "プロジェクト名",
            "target_url": "ターゲットURL",
            "scan_results": "スキャン結果",
            "vulnerability_found": "脆弱性が発見されました",
            "severity_high": "高",
            "severity_medium": "中",
            "severity_low": "低",
            "severity_info": "情報",
            "request": "リクエスト",
            "response": "レスポンス",
            "history": "履歴",
            "payload": "ペイロード",
            "attack_mode": "攻撃モード",
            "sniper": "スナイパー",
            "battering_ram": "バッタリングラム",
            "pitchfork": "ピッチフォーク",
            "cluster_bomb": "クラスターボム",
            "encoding": "エンコーディング",
            "decoding": "デコーディング",
            "url_encode": "URLエンコード",
            "url_decode": "URLデコード",
            "base64_encode": "Base64エンコード",
            "base64_decode": "Base64デコード",
            "hex_encode": "Hexエンコード",
            "hex_decode": "Hexデコード",
            "html_encode": "HTMLエンコード",
            "html_decode": "HTMLデコード",
            "md5_hash": "MD5ハッシュ",
            "sha1_hash": "SHA1ハッシュ",
            "sha256_hash": "SHA256ハッシュ"
        }
        
        # 保存翻译文件
        translations = {
            "zh_CN": zh_cn,
            "en_US": en_us,
            "ja_JP": ja_jp
        }
        
        for lang_code, lang_data in translations.items():
            file_path = self.locale_dir / f"{lang_code}.json"
            if not file_path.exists():
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(lang_data, f, ensure_ascii=False, indent=2)
                logger.info(f"创建翻译文件: {lang_code}.json")
        
    def load_translations(self):
        """加载所有翻译文件"""
        try:
            for lang_file in self.locale_dir.glob("*.json"):
                lang_code = lang_file.stem
                with open(lang_file, 'r', encoding='utf-8') as f:
                    self.translations[lang_code] = json.load(f)
            logger.info(f"加载了 {len(self.translations)} 个语言包")
        except Exception as e:
            logger.error(f"加载翻译文件失败: {e}")
            
    def set_language(self, language_code: str) -> bool:
        """设置当前语言"""
        if language_code in self.translations:
            self.current_language = language_code
            logger.info(f"切换语言: {self.supported_languages.get(language_code, language_code)}")
            return True
        else:
            logger.warning(f"不支持的语言: {language_code}")
            return False
            
    def get_text(self, key: str, **kwargs) -> str:
        """获取翻译文本"""
        translation = self.translations.get(self.current_language, {})
        text = translation.get(key, key)
        
        if kwargs:
            try:
                text = text.format(**kwargs)
            except (KeyError, IndexError):
                pass
                
        return text
        
    def t(self, key: str, **kwargs) -> str:
        """快捷方法获取翻译文本"""
        return self.get_text(key, **kwargs)
        
    def get_supported_languages(self) -> Dict[str, str]:
        """获取支持的语言列表"""
        return self.supported_languages
        
    def get_current_language(self) -> str:
        """获取当前语言"""
        return self.current_language

# 全局国际化管理器实例
_i18n_manager: Optional[I18nManager] = None

def get_i18n() -> I18nManager:
    """获取全局国际化管理器"""
    global _i18n_manager
    if _i18n_manager is None:
        _i18n_manager = I18nManager()
    return _i18n_manager

def set_global_language(language_code: str):
    """设置全局语言"""
    i18n = get_i18n()
    i18n.set_language(language_code)

def _t(key: str, **kwargs) -> str:
    """全局翻译函数"""
    return get_i18n().t(key, **kwargs)