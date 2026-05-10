"""
MITM代理高级流量处理模块
包含：自动解压、编码工具、JSON/XML格式化、十六进制视图、图片预览
"""

import gzip
import zlib
import json
import re
import base64
import binascii
import logging
from typing import Optional, Dict, Any, List, Tuple
from pathlib import Path
from enum import Enum
from datetime import datetime

logger = logging.getLogger(__name__)


class EncodingType(Enum):
    """编码类型"""
    URL_ENCODE = "url_encode"
    URL_DECODE = "url_decode"
    BASE64_ENCODE = "base64_encode"
    BASE64_DECODE = "base64_decode"
    HEX_ENCODE = "hex_encode"
    HEX_DECODE = "hex_decode"
    UNICODE_ENCODE = "unicode_encode"
    UNICODE_DECODE = "unicode_decode"


class TrafficProcessor:
    """流量处理器"""
    
    def __init__(self):
        self._compression_handlers = {
            'gzip': self._decompress_gzip,
            'deflate': self._decompress_deflate,
            'br': self._decompress_brotli,
        }
    
    def auto_decompress(self, body: bytes, encoding: str) -> bytes:
        """自动解压缩内容"""
        if not encoding or encoding.lower() not in self._compression_handlers:
            return body
        
        handler = self._compression_handlers[encoding.lower()]
        try:
            return handler(body)
        except Exception as e:
            logger.warning(f"解压缩失败 [{encoding}]: {e}")
            return body
    
    def _decompress_gzip(self, data: bytes) -> bytes:
        """解压gzip"""
        return gzip.decompress(data)
    
    def _decompress_deflate(self, data: bytes) -> bytes:
        """解压deflate"""
        try:
            return zlib.decompress(data, -zlib.MAX_WBITS)
        except zlib.error:
            return zlib.decompress(data)
    
    def _decompress_brotli(self, data: bytes) -> bytes:
        """解压brotli"""
        try:
            import brotli
            return brotli.decompress(data)
        except ImportError:
            logger.warning("brotli库未安装，无法解压brotli内容")
            return data
        except Exception as e:
            logger.warning(f"brotli解压失败: {e}")
            return data
    
    def reassemble_chunked(self, chunks: List[bytes]) -> bytes:
        """重组分块传输编码"""
        result = b''
        for chunk in chunks:
            # 分块格式: size\r\ndata\r\n
            if b'\r\n' in chunk:
                parts = chunk.split(b'\r\n', 1)
                if len(parts) == 2:
                    try:
                        size = int(parts[0], 16)
                        result += parts[1][:size]
                    except ValueError:
                        result += chunk
            else:
                result += chunk
        return result
    
    def encode_decode(self, data: str, encoding_type: EncodingType) -> str:
        """编码/解码工具"""
        try:
            if encoding_type == EncodingType.URL_ENCODE:
                from urllib.parse import quote
                return quote(data, safe='')
            elif encoding_type == EncodingType.URL_DECODE:
                from urllib.parse import unquote
                return unquote(data)
            elif encoding_type == EncodingType.BASE64_ENCODE:
                return base64.b64encode(data.encode()).decode()
            elif encoding_type == EncodingType.BASE64_DECODE:
                return base64.b64decode(data).decode()
            elif encoding_type == EncodingType.HEX_ENCODE:
                return binascii.hexlify(data.encode()).decode()
            elif encoding_type == EncodingType.HEX_DECODE:
                return binascii.unhexlify(data).decode()
            elif encoding_type == EncodingType.UNICODE_ENCODE:
                return ''.join(f'\\u{ord(c):04x}' for c in data)
            elif encoding_type == EncodingType.UNICODE_DECODE:
                return data.encode().decode('unicode_escape')
            else:
                return data
        except Exception as e:
            logger.error(f"编码/解码失败 [{encoding_type}]: {e}")
            return f"错误: {e}"
    
    def format_json(self, data: str) -> str:
        """格式化JSON"""
        try:
            parsed = json.loads(data)
            return json.dumps(parsed, indent=2, ensure_ascii=False)
        except json.JSONDecodeError as e:
            return f"JSON解析错误: {e}\n\n原始数据:\n{data}"
    
    def format_xml(self, data: str) -> str:
        """格式化XML"""
        try:
            import xml.dom.minidom
            dom = xml.dom.minidom.parseString(data)
            return dom.toprettyxml(indent='  ')
        except Exception as e:
            return f"XML解析错误: {e}\n\n原始数据:\n{data}"
    
    def to_hex_view(self, data: bytes, bytes_per_line: int = 16) -> str:
        """转换为十六进制视图"""
        result = []
        for i in range(0, len(data), bytes_per_line):
            chunk = data[i:i + bytes_per_line]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            result.append(f'{i:08x}  {hex_part:<{bytes_per_line * 3}}  {ascii_part}')
        return '\n'.join(result)
    
    def detect_content_type(self, headers: Dict[str, str]) -> str:
        """检测内容类型"""
        content_type = headers.get('Content-Type', '').lower()
        if 'json' in content_type:
            return 'json'
        elif 'xml' in content_type:
            return 'xml'
        elif 'html' in content_type:
            return 'html'
        elif 'image' in content_type:
            return 'image'
        elif 'javascript' in content_type:
            return 'javascript'
        elif 'css' in content_type:
            return 'css'
        else:
            return 'unknown'
    
    def process_response_body(self, body: bytes, headers: Dict[str, str]) -> Dict[str, Any]:
        """处理响应体"""
        content_type = self.detect_content_type(headers)
        encoding = headers.get('Content-Encoding', '')
        
        # 自动解压
        decompressed_body = self.auto_decompress(body, encoding)
        
        result = {
            'original_size': len(body),
            'decompressed_size': len(decompressed_body),
            'content_type': content_type,
            'encoding': encoding,
            'body': decompressed_body,
        }
        
        # 根据内容类型格式化
        if content_type == 'json':
            try:
                result['formatted'] = self.format_json(decompressed_body.decode('utf-8', errors='replace'))
            except:
                result['formatted'] = decompressed_body.decode('utf-8', errors='replace')
        elif content_type == 'xml':
            result['formatted'] = self.format_xml(decompressed_body.decode('utf-8', errors='replace'))
        else:
            result['formatted'] = decompressed_body.decode('utf-8', errors='replace')
        
        # 十六进制视图
        result['hex_view'] = self.to_hex_view(decompressed_body[:4096])  # 限制大小
        
        return result


class SmartTrafficMarker:
    """智能流量标记器"""
    
    def __init__(self):
        # SQL注入特征
        self.sqli_patterns = [
            r'(?i)(union\s+select|or\s+1\s*=\s*1|and\s+1\s*=\s*1)',
            r'(?i)(drop\s+table|insert\s+into|delete\s+from)',
            r'(?i)(exec\s*\(|execute\s*\()',
            r'(?i)(;\s*--|/\*.*\*/)',
            r"(?i)('\s*or\s*'|'\s*and\s*')",
        ]
        
        # XSS特征
        self.xss_patterns = [
            r'(?i)(<script|javascript:|on\w+\s*=)',
            r'(?i)(alert\s*\(|confirm\s*\(|prompt\s*\()',
            r'(?i)(document\.cookie|document\.write)',
            r'(?i)(<img\s+src|<iframe|<object)',
        ]
        
        # SSRF特征
        self.ssrf_patterns = [
            r'(?i)(http://|https://|ftp://|file://|gopher://)',
            r'(?i)(localhost|127\.0\.0\.1|0\.0\.0\.0)',
            r'(?i)(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)',
            r'(?i)(192\.168\.\d+\.\d+)',
        ]
        
        # 敏感信息特征
        self.sensitive_patterns = {
            'password': r'(?i)(password|passwd|pwd)\s*[:=]\s*\S+',
            'api_key': r'(?i)(api[_-]?key|apikey)\s*[:=]\s*\S+',
            'token': r'(?i)(token|access_token|auth_token)\s*[:=]\s*\S+',
            'secret': r'(?i)(secret|private[_-]?key)\s*[:=]\s*\S+',
            'internal_ip': r'\b(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)\b',
        }
        
        # 服务器指纹
        self.server_fingerprints = {
            'nginx': r'(?i)nginx/([\d.]+)',
            'apache': r'(?i)apache/([\d.]+)',
            'iis': r'(?i)microsoft-iis/([\d.]+)',
            'tomcat': r'(?i)apache-coyote/([\d.]+)',
            'express': r'(?i)x-powered-by:\s*express',
            'django': r'(?i)x-powered-by:\s*django',
            'flask': r'(?i)server:\s*werkzeug',
            'spring': r'(?i)x-powered-by:\s*spring',
        }
    
    def detect_injection_params(self, url: str, body: bytes = None) -> List[Dict[str, str]]:
        """检测潜在注入参数"""
        findings = []
        
        # 检查URL参数
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for param_name, param_values in params.items():
            for value in param_values:
                findings.extend(self._check_value(param_name, value))
        
        # 检查Body
        if body:
            try:
                body_str = body.decode('utf-8', errors='replace')
                # 检查JSON参数
                if body_str.startswith('{'):
                    try:
                        data = json.loads(body_str)
                        for key, value in data.items():
                            if isinstance(value, str):
                                findings.extend(self._check_value(key, value))
                    except:
                        pass
                # 检查表单参数
                elif '&' in body_str:
                    params = parse_qs(body_str)
                    for param_name, param_values in params.items():
                        for value in param_values:
                            findings.extend(self._check_value(param_name, value))
            except:
                pass
        
        return findings
    
    def _check_value(self, param_name: str, value: str) -> List[Dict[str, str]]:
        """检查值是否包含注入特征"""
        findings = []
        
        # SQL注入检查
        for pattern in self.sqli_patterns:
            if re.search(pattern, value):
                findings.append({
                    'type': 'SQLi',
                    'param': param_name,
                    'value': value[:100],
                    'pattern': pattern,
                    'severity': 'high',
                })
                break
        
        # XSS检查
        for pattern in self.xss_patterns:
            if re.search(pattern, value):
                findings.append({
                    'type': 'XSS',
                    'param': param_name,
                    'value': value[:100],
                    'pattern': pattern,
                    'severity': 'high',
                })
                break
        
        # SSRF检查
        for pattern in self.ssrf_patterns:
            if re.search(pattern, value):
                findings.append({
                    'type': 'SSRF',
                    'param': param_name,
                    'value': value[:100],
                    'pattern': pattern,
                    'severity': 'medium',
                })
                break
        
        return findings
    
    def detect_sensitive_info(self, body: bytes, headers: Dict[str, str]) -> List[Dict[str, str]]:
        """检测敏感信息"""
        findings = []
        
        # 检查响应体
        try:
            body_str = body.decode('utf-8', errors='replace')
            for info_type, pattern in self.sensitive_patterns.items():
                matches = re.finditer(pattern, body_str)
                for match in matches:
                    findings.append({
                        'type': info_type,
                        'location': 'body',
                        'value': match.group()[:50],
                        'severity': 'high' if info_type in ['password', 'api_key', 'token', 'secret'] else 'medium',
                    })
        except:
            pass
        
        # 检查响应头
        for header_name, header_value in headers.items():
            for info_type, pattern in self.sensitive_patterns.items():
                if re.search(pattern, header_value):
                    findings.append({
                        'type': info_type,
                        'location': f'header:{header_name}',
                        'value': header_value[:50],
                        'severity': 'high' if info_type in ['password', 'api_key', 'token', 'secret'] else 'medium',
                    })
        
        return findings
    
    def fingerprint_server(self, headers: Dict[str, str]) -> Dict[str, str]:
        """服务器指纹识别"""
        result = {}
        
        for server_name, pattern in self.server_fingerprints.items():
            for header_name, header_value in headers.items():
                match = re.search(pattern, f"{header_name}: {header_value}")
                if match:
                    result[server_name] = match.group(1) if match.lastindex else 'detected'
                    break
        
        return result
    
    def decode_jwt(self, token: str) -> Optional[Dict[str, Any]]:
        """解码JWT令牌"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None
            
            # 解码header和payload
            def decode_part(part):
                # 添加padding
                padding = 4 - len(part) % 4
                if padding != 4:
                    part += '=' * padding
                return base64.urlsafe_b64decode(part)
            
            header = json.loads(decode_part(parts[0]))
            payload = json.loads(decode_part(parts[1]))
            
            return {
                'header': header,
                'payload': payload,
                'signature': parts[2],
            }
        except Exception as e:
            logger.warning(f"JWT解码失败: {e}")
            return None


class TrafficReplayer:
    """流量重放器"""
    
    def __init__(self):
        self._history = []
    
    def replay_request(self, request_data: Dict[str, Any], 
                      proxy: Optional[str] = None) -> Dict[str, Any]:
        """重放单个请求"""
        import requests
        from urllib.parse import urlparse
        
        try:
            # 构建请求
            method = request_data.get('method', 'GET')
            url = request_data.get('url', '')
            headers = request_data.get('headers', {})
            body = request_data.get('body', '')
            
            # 准备proxies
            proxies = None
            if proxy:
                proxies = {
                    'http': proxy,
                    'https': proxy,
                }
            
            # 发送请求
            start_time = datetime.utcnow()
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                data=body.encode() if body else None,
                proxies=proxies,
                timeout=30,
                verify=False,
                allow_redirects=False,
            )
            end_time = datetime.utcnow()
            
            response_time = (end_time - start_time).total_seconds()
            
            return {
                'success': True,
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'body': response.text,
                'response_time': response_time,
                'timestamp': end_time.isoformat(),
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat(),
            }
    
    def batch_replay(self, requests_data: List[Dict[str, Any]], 
                    concurrent: bool = False,
                    proxy: Optional[str] = None) -> List[Dict[str, Any]]:
        """批量重放请求"""
        results = []
        
        if concurrent:
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = [
                    executor.submit(self.replay_request, req, proxy)
                    for req in requests_data
                ]
                for future in concurrent.futures.as_completed(futures):
                    results.append(future.result())
        else:
            for req in requests_data:
                results.append(self.replay_request(req, proxy))
        
        return results
    
    def export_as_curl(self, request_data: Dict[str, Any]) -> str:
        """导出为curl命令"""
        method = request_data.get('method', 'GET')
        url = request_data.get('url', '')
        headers = request_data.get('headers', {})
        body = request_data.get('body', '')
        
        curl_cmd = f"curl -X {method} '{url}'"
        
        for key, value in headers.items():
            curl_cmd += f" \\\n  -H '{key}: {value}'"
        
        if body:
            curl_cmd += f" \\\n  -d '{body}'"
        
        return curl_cmd
    
    def export_as_python_requests(self, request_data: Dict[str, Any]) -> str:
        """导出为Python requests代码"""
        method = request_data.get('method', 'GET').lower()
        url = request_data.get('url', '')
        headers = request_data.get('headers', {})
        body = request_data.get('body', '')
        
        code = f"import requests\n\n"
        code += f"url = '{url}'\n"
        code += f"headers = {json.dumps(headers, indent=2)}\n"
        
        if body:
            code += f"data = '''{body}'''\n\n"
            code += f"response = requests.{method}(url, headers=headers, data=data)\n"
        else:
            code += f"\nresponse = requests.{method}(url, headers=headers)\n"
        
        code += f"\nprint(response.status_code)\n"
        code += f"print(response.text)\n"
        
        return code
    
    def compare_responses(self, original: Dict[str, Any], 
                         replayed: Dict[str, Any]) -> Dict[str, Any]:
        """对比两个响应的差异"""
        result = {
            'status_code_changed': original.get('status_code') != replayed.get('status_code'),
            'headers_changed': {},
            'body_changed': False,
            'response_time_diff': 0,
        }
        
        # 对比状态码
        if result['status_code_changed']:
            result['status_code_original'] = original.get('status_code')
            result['status_code_replayed'] = replayed.get('status_code')
        
        # 对比响应头
        orig_headers = original.get('headers', {})
        replay_headers = replayed.get('headers', {})
        
        all_keys = set(list(orig_headers.keys()) + list(replay_headers.keys()))
        for key in all_keys:
            orig_val = orig_headers.get(key, '')
            replay_val = replay_headers.get(key, '')
            if orig_val != replay_val:
                result['headers_changed'][key] = {
                    'original': orig_val,
                    'replayed': replay_val,
                }
        
        # 对比响应体
        orig_body = original.get('body', '')
        replay_body = replayed.get('body', '')
        if orig_body != replay_body:
            result['body_changed'] = True
            result['body_diff'] = self._compute_diff(orig_body, replay_body)
        
        # 响应时间差异
        orig_time = original.get('response_time', 0)
        replay_time = replayed.get('response_time', 0)
        result['response_time_diff'] = replay_time - orig_time
        
        return result
    
    def _compute_diff(self, text1: str, text2: str) -> List[Dict[str, Any]]:
        """计算文本差异"""
        import difflib
        
        diff = difflib.unified_diff(
            text1.splitlines(keepends=True),
            text2.splitlines(keepends=True),
            lineterm='',
        )
        
        return list(diff)
