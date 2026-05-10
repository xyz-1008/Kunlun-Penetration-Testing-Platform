"""
Nuclei DSL辅助函数库
实现Nuclei模板中使用的所有内置变量和辅助函数

内置变量:
    BaseURL / RootURL / Hostname / Host / Port / Scheme
    Timestamp / RandomString / RandInt / RandomInt
    RandomLowercaseString / RandomUppercaseString / RandomAlphanumericString
    date_time / date / time / unix_time

辅助函数:
    编码: base64 / base64_decode / base64_py / url_encode / url_decode
          hex_encode / hex_decode / html_escape / html_unescape
    字符串: to_lower / to_upper / replace / replace_regex / trim
            split / join / contains / starts_with / ends_with
            reverse / repeat / substring / concat / regex
    哈希: md5 / sha1 / sha256 / sha512 / mmh3
    网络: resolve / ip_format
    压缩: zlib / zlib_decode / gzip / gzip_decode / gunzip
    数学: int / float / abs / min / max / add / subtract / multiply / divide
          mod / pow / round / ceil / floor / sqrt / log / sin / cos / tan
    进制: binary / octal / hex / bin / oct
"""

import re
import hashlib
import base64
import random
import string
import time
import socket
import ipaddress
import urllib.parse
from typing import Any, Dict, Optional, List, Union
from datetime import datetime


_VARIABLE_PATTERN = re.compile(r"\{\{(.+?)\}\}")
_FUNC_CALL_PATTERN = re.compile(r'(\w+)\(([^)]*)\)')
_NESTED_FUNC_PATTERN = re.compile(r'(\w+)\(((?:[^()]|\([^()]*\))*)\)')


class NucleiVariableContext:
    """Nuclei变量上下文

    管理模板执行过程中的所有变量，包括:
    - 内置变量 (BaseURL, Hostname, Port 等)
    - 模板变量 (variables 块定义)
    - 提取变量 (extractors 提取结果)
    - Cookie 变量 (cookie-reuse 机制)

    支持嵌套函数调用: {{base64(url_encode(body))}}
    """

    def __init__(self, base_url: str = "", target_host: str = "", target_port: int = 80):
        self._variables: Dict[str, Any] = {}
        self._extracted: Dict[str, Any] = {}
        self._cookies: Dict[str, str] = {}
        self._base_url = base_url
        self._target_host = target_host
        self._target_port = target_port
        self._scheme = "https" if target_port == 443 else "http"

    @property
    def base_url(self) -> str:
        return self._base_url

    @base_url.setter
    def base_url(self, value: str):
        self._base_url = value

    def set_variable(self, name: str, value: Any):
        """设置模板变量"""
        self._variables[name] = value

    def get_variable(self, name: str) -> Any:
        """获取模板变量"""
        return self._variables.get(name)

    def set_extracted(self, name: str, value: Any):
        """设置提取变量"""
        self._extracted[name] = value

    def get_extracted(self, name: str) -> Any:
        """获取提取变量"""
        return self._extracted.get(name)

    def set_cookie(self, name: str, value: str):
        """设置Cookie"""
        self._cookies[name] = value

    def get_cookies(self) -> Dict[str, str]:
        """获取所有Cookie"""
        return dict(self._cookies)

    def resolve(self, text: str, response_body: str = "", response_headers: Dict[str, str] = None) -> str:
        """解析文本中的所有变量引用

        支持:
        - 简单变量: {{BaseURL}}
        - 函数调用: {{base64("hello")}}
        - 嵌套调用: {{base64(url_encode(body))}}
        - 提取变量: {{extracted_var}}

        Args:
            text: 包含变量引用的文本
            response_body: 当前响应体 (用于 body 变量)
            response_headers: 当前响应头

        Returns:
            解析后的文本
        """
        if not text or "{{" not in text:
            return text

        def _replace(match: re.Match) -> str:
            expr = match.group(1).strip()
            return str(self._evaluate_expression(expr, response_body, response_headers or {}))

        return _VARIABLE_PATTERN.sub(_replace, text)

    def _evaluate_expression(self, expr: str, response_body: str, response_headers: Dict[str, str]) -> Any:
        """评估单个表达式，支持嵌套函数调用"""
        if _NESTED_FUNC_PATTERN.match(expr):
            return self._call_helper_function(expr, response_body, response_headers)

        builtins = self._get_builtin_variables()

        if expr in builtins:
            return builtins[expr]

        if expr in self._variables:
            return self._variables[expr]

        if expr in self._extracted:
            return self._extracted[expr]

        if expr == "body" and response_body:
            return response_body

        return "{{" + expr + "}}"

    def _get_builtin_variables(self) -> Dict[str, str]:
        """获取所有内置变量"""
        return {
            "BaseURL": self._base_url,
            "RootURL": self._get_root_url(),
            "Hostname": self._target_host,
            "Host": self._target_host,
            "Port": str(self._target_port),
            "Scheme": self._scheme,
            "Timestamp": str(int(time.time())),
            "RandomString": self._random_string(8),
            "RandInt": str(random.randint(0, 999999)),
            "RandomInt": str(random.randint(0, 999999)),
            "RandomLowercaseString": self._random_lowercase(8),
            "RandomUppercaseString": self._random_uppercase(8),
            "RandomAlphanumericString": self._random_alphanumeric(8),
            "date_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "date": datetime.now().strftime("%Y-%m-%d"),
            "time": datetime.now().strftime("%H:%M:%S"),
            "unix_time": str(int(time.time())),
        }

    def _get_root_url(self) -> str:
        """获取根URL (scheme + host + port)"""
        if self._base_url:
            parsed = urllib.parse.urlparse(self._base_url)
            return f"{parsed.scheme}://{parsed.netloc}"
        return f"{self._scheme}://{self._target_host}:{self._target_port}"

    def _call_helper_function(self, expr: str, response_body: str, response_headers: Dict[str, str]) -> str:
        """调用辅助函数，支持嵌套调用

        处理流程:
        1. 解析函数名和参数
        2. 递归解析参数中的嵌套函数调用
        3. 解析参数中的变量引用
        4. 调用对应的辅助函数
        """
        match = _NESTED_FUNC_PATTERN.match(expr)
        if not match:
            return expr

        func_name = match.group(1)
        arg_str = match.group(2)

        args = self._parse_args(arg_str)

        resolved_args = []
        for arg in args:
            arg = arg.strip()
            if arg.startswith('"') and arg.endswith('"'):
                resolved_args.append(arg[1:-1])
            elif arg.startswith("'") and arg.endswith("'"):
                resolved_args.append(arg[1:-1])
            elif _NESTED_FUNC_PATTERN.match(arg):
                resolved_args.append(self._call_helper_function(arg, response_body, response_headers))
            elif arg in self._variables:
                resolved_args.append(str(self._variables[arg]))
            elif arg in self._extracted:
                resolved_args.append(str(self._extracted[arg]))
            elif arg == "body" and response_body:
                resolved_args.append(response_body)
            else:
                builtins = self._get_builtin_variables()
                if arg in builtins:
                    resolved_args.append(builtins[arg])
                else:
                    resolved_args.append(arg)

        return NucleiHelpers.call(func_name, *resolved_args)

    @staticmethod
    def _parse_args(arg_str: str) -> List[str]:
        """解析函数参数，正确处理嵌套括号和引号"""
        if not arg_str.strip():
            return []
        args = []
        current = ""
        in_quotes = False
        quote_char = None
        depth = 0

        for ch in arg_str:
            if ch in ('"', "'") and not in_quotes:
                in_quotes = True
                quote_char = ch
                current += ch
            elif ch == quote_char and in_quotes:
                in_quotes = False
                quote_char = None
                current += ch
            elif ch == '(':
                depth += 1
                current += ch
            elif ch == ')':
                depth -= 1
                current += ch
            elif ch == ',' and not in_quotes and depth == 0:
                args.append(current.strip())
                current = ""
            else:
                current += ch

        if current.strip():
            args.append(current.strip())

        return args

    @staticmethod
    def _random_string(length: int = 8) -> str:
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    @staticmethod
    def _random_lowercase(length: int = 8) -> str:
        return ''.join(random.choices(string.ascii_lowercase, k=length))

    @staticmethod
    def _random_uppercase(length: int = 8) -> str:
        return ''.join(random.choices(string.ascii_uppercase, k=length))

    @staticmethod
    def _random_alphanumeric(length: int = 8) -> str:
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


class NucleiHelpers:
    """Nuclei辅助函数库

    所有函数均为静态方法，通过 call() 统一调度。
    支持 60+ 辅助函数，覆盖编码/字符串/哈希/网络/压缩/数学/进制等类别。
    """

    @classmethod
    def call(cls, func_name: str, *args: str) -> str:
        """调用辅助函数

        Args:
            func_name: 函数名
            *args: 函数参数

        Returns:
            函数执行结果字符串
        """
        func_map = {
            "base64": cls.base64_encode,
            "base64_decode": cls.base64_decode,
            "base64_py": cls.base64_encode,
            "url_encode": cls.url_encode,
            "url_decode": cls.url_decode,
            "hex_encode": cls.hex_encode,
            "hex_decode": cls.hex_decode,
            "to_lower": cls.to_lower,
            "to_upper": cls.to_upper,
            "replace": cls.replace,
            "replace_regex": cls.replace_regex,
            "regex": cls.regex_extract,
            "md5": cls.md5,
            "sha1": cls.sha1,
            "sha256": cls.sha256,
            "sha512": cls.sha512,
            "mmh3": cls.mmh3,
            "contains": cls.contains,
            "len": cls.length,
            "starts_with": cls.starts_with,
            "ends_with": cls.ends_with,
            "to_number": cls.to_number,
            "to_string": cls.to_string,
            "trim": cls.trim,
            "split": cls.split_func,
            "join": cls.join_func,
            "reverse": cls.reverse,
            "repeat": cls.repeat,
            "substring": cls.substring,
            "concat": cls.concat,
            "int": cls.to_int,
            "float": cls.to_float,
            "abs": cls.abs_value,
            "min": cls.min_value,
            "max": cls.max_value,
            "add": cls.add,
            "subtract": cls.subtract,
            "multiply": cls.multiply,
            "divide": cls.divide,
            "mod": cls.mod,
            "pow": cls.pow_value,
            "round": cls.round_value,
            "ceil": cls.ceil_value,
            "floor": cls.floor_value,
            "sqrt": cls.sqrt_value,
            "log": cls.log_value,
            "sin": cls.sin_value,
            "cos": cls.cos_value,
            "tan": cls.tan_value,
            "escape_html": cls.escape_html,
            "unescape_html": cls.unescape_html,
            "html_escape": cls.escape_html,
            "html_unescape": cls.unescape_html,
            "binary": cls.to_binary,
            "octal": cls.to_octal,
            "hex": cls.to_hex,
            "bin": cls.to_binary,
            "oct": cls.to_octal,
            "zlib": cls.zlib_compress,
            "zlib_decode": cls.zlib_decompress,
            "gzip": cls.gzip_compress,
            "gzip_decode": cls.gzip_decompress,
            "gunzip": cls.gzip_decompress,
            "resolve": cls.resolve_dns,
            "ip_format": cls.ip_format,
        }

        handler = func_map.get(func_name)
        if handler:
            try:
                return handler(*args)
            except Exception:
                return ""
        return ""

    @staticmethod
    def base64_encode(s: str) -> str:
        return base64.b64encode(s.encode("utf-8", errors="ignore")).decode()

    @staticmethod
    def base64_decode(s: str) -> str:
        try:
            return base64.b64decode(s).decode("utf-8", errors="ignore")
        except Exception:
            return ""

    @staticmethod
    def url_encode(s: str) -> str:
        return urllib.parse.quote(s, safe="")

    @staticmethod
    def url_decode(s: str) -> str:
        return urllib.parse.unquote(s)

    @staticmethod
    def hex_encode(s: str) -> str:
        return s.encode("utf-8", errors="ignore").hex()

    @staticmethod
    def hex_decode(s: str) -> str:
        try:
            return bytes.fromhex(s).decode("utf-8", errors="ignore")
        except Exception:
            return ""

    @staticmethod
    def to_lower(s: str) -> str:
        return s.lower()

    @staticmethod
    def to_upper(s: str) -> str:
        return s.upper()

    @staticmethod
    def replace(s: str, old: str, new: str) -> str:
        return s.replace(old, new)

    @staticmethod
    def replace_regex(s: str, pattern: str, replacement: str) -> str:
        """正则替换"""
        try:
            return re.sub(pattern, replacement, s)
        except re.error:
            return s

    @staticmethod
    def regex_extract(s: str, pattern: str) -> str:
        m = re.search(pattern, s)
        return m.group(0) if m else ""

    @staticmethod
    def md5(s: str) -> str:
        return hashlib.md5(s.encode("utf-8", errors="ignore")).hexdigest()

    @staticmethod
    def sha1(s: str) -> str:
        return hashlib.sha1(s.encode("utf-8", errors="ignore")).hexdigest()

    @staticmethod
    def sha256(s: str) -> str:
        return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()

    @staticmethod
    def sha512(s: str) -> str:
        return hashlib.sha512(s.encode("utf-8", errors="ignore")).hexdigest()

    @staticmethod
    def mmh3(s: str) -> str:
        """MurmurHash3 32-bit - 与Shodan Favicon算法一致"""
        data = s.encode("utf-8", errors="ignore")
        c1 = 0xCC9E2D51
        c2 = 0x1B873593
        length = len(data)
        h1 = 0

        nblocks = length // 4
        for i in range(nblocks):
            k1 = int.from_bytes(data[i * 4:(i + 1) * 4], "little", signed=False)
            k1 = (k1 * c1) & 0xFFFFFFFF
            k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
            k1 = (k1 * c2) & 0xFFFFFFFF
            h1 ^= k1
            h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
            h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

        tail = data[nblocks * 4:]
        k1 = 0
        if len(tail) >= 3:
            k1 ^= tail[2] << 16
        if len(tail) >= 2:
            k1 ^= tail[1] << 8
        if len(tail) >= 1:
            k1 ^= tail[0]
            k1 = (k1 * c1) & 0xFFFFFFFF
            k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
            k1 = (k1 * c2) & 0xFFFFFFFF
            h1 ^= k1

        h1 ^= length
        h1 ^= (h1 >> 16)
        h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
        h1 ^= (h1 >> 13)
        h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
        h1 ^= (h1 >> 16)

        return str(h1)

    @staticmethod
    def resolve_dns(hostname: str) -> str:
        """DNS解析 - 返回第一个IPv4地址"""
        try:
            addr_info = socket.getaddrinfo(hostname, None, socket.AF_INET)
            if addr_info:
                return addr_info[0][4][0]
        except (socket.gaierror, socket.herror):
            pass
        return ""

    @staticmethod
    def ip_format(ip: str, fmt: str = "decimal") -> str:
        """IP地址格式化

        Args:
            ip: IP地址字符串
            fmt: 格式类型 (decimal/hex/octal)

        Returns:
            格式化后的IP字符串
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            if fmt == "decimal":
                return str(int(ip_obj))
            elif fmt == "hex":
                return hex(int(ip_obj))
            elif fmt == "octal":
                return oct(int(ip_obj))
        except ValueError:
            pass
        return ip

    @staticmethod
    def contains(s: str, substr: str) -> str:
        return str(substr in s).lower()

    @staticmethod
    def length(s: str) -> str:
        return str(len(s))

    @staticmethod
    def starts_with(s: str, prefix: str) -> str:
        return str(s.startswith(prefix)).lower()

    @staticmethod
    def ends_with(s: str, suffix: str) -> str:
        return str(s.endswith(suffix)).lower()

    @staticmethod
    def to_number(s: str) -> str:
        try:
            return str(int(s))
        except ValueError:
            try:
                return str(float(s))
            except ValueError:
                return "0"

    @staticmethod
    def to_string(v: str) -> str:
        return str(v)

    @staticmethod
    def trim(s: str) -> str:
        return s.strip()

    @staticmethod
    def split_func(s: str, sep: str = ",") -> str:
        parts = s.split(sep)
        return parts[0] if parts else ""

    @staticmethod
    def join_func(sep: str, *args: str) -> str:
        return sep.join(args)

    @staticmethod
    def reverse(s: str) -> str:
        return s[::-1]

    @staticmethod
    def repeat(s: str, count: str) -> str:
        return s * int(count)

    @staticmethod
    def substring(s: str, start: str, end: str = "") -> str:
        si = int(start)
        if end:
            return s[si:int(end)]
        return s[si:]

    @staticmethod
    def concat(*args: str) -> str:
        return "".join(args)

    @staticmethod
    def to_int(s: str) -> str:
        try:
            return str(int(float(s)))
        except (ValueError, TypeError):
            return "0"

    @staticmethod
    def to_float(s: str) -> str:
        try:
            return str(float(s))
        except (ValueError, TypeError):
            return "0.0"

    @staticmethod
    def abs_value(s: str) -> str:
        return str(abs(float(s)))

    @staticmethod
    def min_value(a: str, b: str) -> str:
        return str(min(float(a), float(b)))

    @staticmethod
    def max_value(a: str, b: str) -> str:
        return str(max(float(a), float(b)))

    @staticmethod
    def add(a: str, b: str) -> str:
        return str(float(a) + float(b))

    @staticmethod
    def subtract(a: str, b: str) -> str:
        return str(float(a) - float(b))

    @staticmethod
    def multiply(a: str, b: str) -> str:
        return str(float(a) * float(b))

    @staticmethod
    def divide(a: str, b: str) -> str:
        try:
            return str(float(a) / float(b))
        except ZeroDivisionError:
            return "0"

    @staticmethod
    def mod(a: str, b: str) -> str:
        try:
            return str(int(float(a)) % int(float(b)))
        except (ValueError, ZeroDivisionError):
            return "0"

    @staticmethod
    def pow_value(a: str, b: str) -> str:
        return str(float(a) ** float(b))

    @staticmethod
    def round_value(s: str, ndigits: str = "0") -> str:
        return str(round(float(s), int(ndigits)))

    @staticmethod
    def ceil_value(s: str) -> str:
        import math
        return str(math.ceil(float(s)))

    @staticmethod
    def floor_value(s: str) -> str:
        import math
        return str(math.floor(float(s)))

    @staticmethod
    def sqrt_value(s: str) -> str:
        import math
        return str(math.sqrt(float(s)))

    @staticmethod
    def log_value(s: str) -> str:
        import math
        return str(math.log(float(s)))

    @staticmethod
    def sin_value(s: str) -> str:
        import math
        return str(math.sin(float(s)))

    @staticmethod
    def cos_value(s: str) -> str:
        import math
        return str(math.cos(float(s)))

    @staticmethod
    def tan_value(s: str) -> str:
        import math
        return str(math.tan(float(s)))

    @staticmethod
    def escape_html(s: str) -> str:
        import html
        return html.escape(s)

    @staticmethod
    def unescape_html(s: str) -> str:
        import html
        return html.unescape(s)

    @staticmethod
    def to_binary(s: str) -> str:
        try:
            return bin(int(s))[2:]
        except ValueError:
            return "0"

    @staticmethod
    def to_octal(s: str) -> str:
        try:
            return oct(int(s))[2:]
        except ValueError:
            return "0"

    @staticmethod
    def to_hex(s: str) -> str:
        try:
            return hex(int(s))[2:]
        except ValueError:
            return "0"

    @staticmethod
    def zlib_compress(s: str) -> str:
        import zlib
        return base64.b64encode(zlib.compress(s.encode("utf-8", errors="ignore"))).decode()

    @staticmethod
    def zlib_decompress(s: str) -> str:
        import zlib
        try:
            return zlib.decompress(base64.b64decode(s)).decode("utf-8", errors="ignore")
        except Exception:
            return ""

    @staticmethod
    def gzip_compress(s: str) -> str:
        import gzip
        return base64.b64encode(gzip.compress(s.encode("utf-8", errors="ignore"))).decode()

    @staticmethod
    def gzip_decompress(s: str) -> str:
        import gzip
        try:
            return gzip.decompress(base64.b64decode(s)).decode("utf-8", errors="ignore")
        except Exception:
            return ""


def evaluate_dsl_expression(expr: str, body: str = "", headers: Dict[str, str] = None,
                            status_code: int = 0, content_length: int = 0) -> bool:
    """评估DSL表达式 - 安全沙箱执行

    在受限命名空间中执行DSL表达式，禁止所有危险操作:
    - 禁止: eval/exec/compile/open/__import__/os/sys/subprocess
    - 允许: 字符串操作/数学运算/类型转换/内置安全函数

    Args:
        expr: DSL表达式字符串
        body: 响应体
        headers: 响应头字典
        status_code: HTTP状态码
        content_length: 响应体大小

    Returns:
        表达式求值结果 (bool)
    """
    if headers is None:
        headers = {}

    safe_locals = {
        "body": body,
        "all_headers": "\n".join(f"{k}: {v}" for k, v in headers.items()),
        "status_code": status_code,
        "content_length": content_length,
        "contains": lambda s, sub: sub in s,
        "len": len,
        "starts_with": str.startswith,
        "ends_with": str.endswith,
        "regex": lambda s, p: bool(re.search(p, s)),
        "to_number": lambda s: int(s) if s.isdigit() else 0,
        "to_string": str,
        "to_lower": str.lower,
        "to_upper": str.upper,
        "trim": str.strip,
        "True": True,
        "False": False,
        "true": True,
        "false": False,
        "None": None,
        "int": int,
        "float": float,
        "str": str,
        "bool": bool,
        "min": min,
        "max": max,
        "abs": abs,
        "round": round,
        "sum": sum,
        "any": any,
        "all": all,
        "sorted": sorted,
        "reversed": reversed,
        "enumerate": enumerate,
        "zip": zip,
        "range": range,
        "list": list,
        "dict": dict,
        "tuple": tuple,
        "set": set,
        "type": type,
        "isinstance": isinstance,
        "hasattr": hasattr,
        "getattr": getattr,
        "print": lambda *a, **kw: None,
    }

    for key, value in headers.items():
        safe_key = f"header_{key.replace('-', '_').lower()}"
        safe_locals[safe_key] = value

    forbidden = [
        "__import__", "eval", "exec", "compile", "open", "input",
        "__builtins__", "__builtin__", "__subclasses__", "__bases__",
        "__mro__", "__globals__", "__code__", "__class__",
        "os", "sys", "subprocess", "shutil", "socket", "requests",
        "urllib", "http", "ftp", "telnet", "ssh",
        "import", "from", "as", "with", "yield",
        "globals", "locals", "vars", "dir",
        "getattr", "setattr", "delattr",
        "__getattribute__", "__setattr__", "__delattr__",
        "__init__", "__new__", "__del__",
        "__reduce__", "__reduce_ex__",
    ]

    for forbidden_word in forbidden:
        if forbidden_word in expr:
            return False

    try:
        result = eval(expr, {"__builtins__": {}}, safe_locals)
        if isinstance(result, bool):
            return result
        if isinstance(result, str):
            return result.lower() == "true"
        return bool(result)
    except Exception:
        return False
