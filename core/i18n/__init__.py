"""
昆仑安全测试平台 - 国际化模块
提供多语言支持
"""

from .internationalization import (
    I18nManager,
    get_i18n,
    set_global_language,
    _t
)

__all__ = [
    'I18nManager',
    'get_i18n',
    'set_global_language',
    '_t'
]