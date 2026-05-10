"""
高级编码解码工具模块
基于20年渗透测试经验的多格式编码解码工具
支持智能识别、批量处理和自定义编码规则
"""

import base64
import binascii
import urllib.parse
import html
import hashlib
import logging
import re
from typing import Dict, List, Optional, Callable, Any, Tuple
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)

class EncodingType(Enum):
    """编码类型枚举"""
    BASE64 = "base64"
    URL = "url"
    HTML = "html"
    HEX = "hex"
    ASCII = "ascii"
    UNICODE = "unicode"
    BINARY = "binary"
    ROT13 = "rot13"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    CUSTOM = "custom"

@dataclass
class EncodingResult:
    """编码结果"""
    input_data: str
    output_data: str
    encoding_type: EncodingType
    operation: str  # encode/decode
    timestamp: datetime
    
    def to_dict(self) -> Dict:
        """转换为字典格式"""
        return {
            'input_data': self.input_data,
            'output_data': self.output_data,
            'encoding_type': self.encoding_type.value,
            'operation': self.operation,
            'timestamp': self.timestamp.isoformat()
        }

class AdvancedEncoderDecoder:
    """高级编码解码工具"""
    
    def __init__(self):
        # 编码器注册表
        self.encoders: Dict[str, Callable] = {}
        self.decoders: Dict[str, Callable] = {}
        
        # 结果存储
        self.encoding_history: List[EncodingResult] = []
        
        # 自定义编码规则
        self.custom_rules: Dict[str, Callable] = {}
        
        # 注册内置编码器
        self._register_builtin_encoders()
        
        logger.info("高级编码解码工具初始化完成")
    
    def _register_builtin_encoders(self):
        """注册内置编码器"""
        # Base64编码解码
        self.encoders[EncodingType.BASE64.value] = self._encode_base64
        self.decoders[EncodingType.BASE64.value] = self._decode_base64
        
        # URL编码解码
        self.encoders[EncodingType.URL.value] = self._encode_url
        self.decoders[EncodingType.URL.value] = self._decode_url
        
        # HTML编码解码
        self.encoders[EncodingType.HTML.value] = self._encode_html
        self.decoders[EncodingType.HTML.value] = self._decode_html
        
        # Hex编码解码
        self.encoders[EncodingType.HEX.value] = self._encode_hex
        self.decoders[EncodingType.HEX.value] = self._decode_hex
        
        # ASCII编码解码
        self.encoders[EncodingType.ASCII.value] = self._encode_ascii
        self.decoders[EncodingType.ASCII.value] = self._decode_ascii
        
        # Unicode编码解码
        self.encoders[EncodingType.UNICODE.value] = self._encode_unicode
        self.decoders[EncodingType.UNICODE.value] = self._decode_unicode
        
        # 二进制编码解码
        self.encoders[EncodingType.BINARY.value] = self._encode_binary
        self.decoders[EncodingType.BINARY.value] = self._decode_binary
        
        # ROT13编码解码
        self.encoders[EncodingType.ROT13.value] = self._encode_rot13
        self.decoders[EncodingType.ROT13.value] = self._decode_rot13
        
        # 哈希函数（只有编码）
        self.encoders[EncodingType.MD5.value] = self._encode_md5
        self.encoders[EncodingType.SHA1.value] = self._encode_sha1
        self.encoders[EncodingType.SHA256.value] = self._encode_sha256
    
    def encode(self, data: str, encoding_type: EncodingType) -> EncodingResult:
        """编码数据"""
        try:
            if encoding_type.value not in self.encoders:
                raise ValueError(f"不支持的编码类型: {encoding_type}")
            
            encoder_func = self.encoders[encoding_type.value]
            encoded_data = encoder_func(data)
            
            result = EncodingResult(
                input_data=data,
                output_data=encoded_data,
                encoding_type=encoding_type,
                operation="encode",
                timestamp=datetime.now()
            )
            
            self.encoding_history.append(result)
            logger.info(f"编码完成: {encoding_type.value}")
            return result
            
        except Exception as e:
            logger.error(f"编码失败: {e}")
            raise
    
    def decode(self, data: str, encoding_type: EncodingType) -> EncodingResult:
        """解码数据"""
        try:
            if encoding_type.value not in self.decoders:
                raise ValueError(f"不支持的编码类型: {encoding_type}")
            
            decoder_func = self.decoders[encoding_type.value]
            decoded_data = decoder_func(data)
            
            result = EncodingResult(
                input_data=data,
                output_data=decoded_data,
                encoding_type=encoding_type,
                operation="decode",
                timestamp=datetime.now()
            )
            
            self.encoding_history.append(result)
            logger.info(f"解码完成: {encoding_type.value}")
            return result
            
        except Exception as e:
            logger.error(f"解码失败: {e}")
            raise
    
    def batch_process(self, data_list: List[str], operation: str, encoding_type: EncodingType) -> List[EncodingResult]:
        """批量处理数据"""
        results = []
        
        for data in data_list:
            if operation == "encode":
                result = self.encode(data, encoding_type)
            elif operation == "decode":
                result = self.decode(data, encoding_type)
            else:
                raise ValueError(f"不支持的操作: {operation}")
            
            results.append(result)
        
        return results
    
    def auto_detect(self, data: str) -> List[Tuple[EncodingType, float]]:
        """自动检测编码类型"""
        detection_results = []
        
        # Base64检测
        base64_confidence = self._detect_base64(data)
        if base64_confidence > 0:
            detection_results.append((EncodingType.BASE64, base64_confidence))
        
        # URL编码检测
        url_confidence = self._detect_url(data)
        if url_confidence > 0:
            detection_results.append((EncodingType.URL, url_confidence))
        
        # HTML编码检测
        html_confidence = self._detect_html(data)
        if html_confidence > 0:
            detection_results.append((EncodingType.HTML, html_confidence))
        
        # Hex编码检测
        hex_confidence = self._detect_hex(data)
        if hex_confidence > 0:
            detection_results.append((EncodingType.HEX, hex_confidence))
        
        # 按置信度排序
        detection_results.sort(key=lambda x: x[1], reverse=True)
        
        return detection_results
    
    # ========== 内置编码器实现 ==========
    
    def _encode_base64(self, data: str) -> str:
        """Base64编码"""
        return base64.b64encode(data.encode('utf-8')).decode('utf-8')
    
    def _decode_base64(self, data: str) -> str:
        """Base64解码"""
        try:
            return base64.b64decode(data).decode('utf-8')
        except (binascii.Error, UnicodeDecodeError):
            # 尝试URL安全的Base64解码
            try:
                return base64.urlsafe_b64decode(data).decode('utf-8')
            except:
                raise ValueError("Base64解码失败")
    
    def _encode_url(self, data: str) -> str:
        """URL编码"""
        return urllib.parse.quote(data)
    
    def _decode_url(self, data: str) -> str:
        """URL解码"""
        return urllib.parse.unquote(data)
    
    def _encode_html(self, data: str) -> str:
        """HTML编码"""
        return html.escape(data)
    
    def _decode_html(self, data: str) -> str:
        """HTML解码"""
        return html.unescape(data)
    
    def _encode_hex(self, data: str) -> str:
        """Hex编码"""
        return data.encode('utf-8').hex()
    
    def _decode_hex(self, data: str) -> str:
        """Hex解码"""
        try:
            return bytes.fromhex(data).decode('utf-8')
        except ValueError:
            raise ValueError("Hex解码失败")
    
    def _encode_ascii(self, data: str) -> str:
        """ASCII编码"""
        return ' '.join(str(ord(c)) for c in data)
    
    def _decode_ascii(self, data: str) -> str:
        """ASCII解码"""
        try:
            ascii_codes = data.split()
            return ''.join(chr(int(code)) for code in ascii_codes)
        except ValueError:
            raise ValueError("ASCII解码失败")
    
    def _encode_unicode(self, data: str) -> str:
        """Unicode编码"""
        return ' '.join(f'\\u{ord(c):04x}' for c in data)
    
    def _decode_unicode(self, data: str) -> str:
        """Unicode解码"""
        try:
            # 匹配 \uXXXX 格式
            unicode_pattern = r'\\u([0-9a-fA-F]{4})'
            matches = re.findall(unicode_pattern, data)
            
            if matches:
                return ''.join(chr(int(match, 16)) for match in matches)
            else:
                # 尝试直接解码
                return data.encode('utf-8').decode('unicode_escape')
        except (ValueError, UnicodeDecodeError):
            raise ValueError("Unicode解码失败")
    
    def _encode_binary(self, data: str) -> str:
        """二进制编码"""
        return ' '.join(format(ord(c), '08b') for c in data)
    
    def _decode_binary(self, data: str) -> str:
        """二进制解码"""
        try:
            binary_codes = data.split()
            return ''.join(chr(int(code, 2)) for code in binary_codes)
        except ValueError:
            raise ValueError("二进制解码失败")
    
    def _encode_rot13(self, data: str) -> str:
        """ROT13编码"""
        result = []
        for char in data:
            if 'a' <= char <= 'z':
                result.append(chr((ord(char) - ord('a') + 13) % 26 + ord('a')))
            elif 'A' <= char <= 'Z':
                result.append(chr((ord(char) - ord('A') + 13) % 26 + ord('A')))
            else:
                result.append(char)
        return ''.join(result)
    
    def _decode_rot13(self, data: str) -> str:
        """ROT13解码（与编码相同）"""
        return self._encode_rot13(data)
    
    def _encode_md5(self, data: str) -> str:
        """MD5哈希"""
        return hashlib.md5(data.encode('utf-8')).hexdigest()
    
    def _encode_sha1(self, data: str) -> str:
        """SHA1哈希"""
        return hashlib.sha1(data.encode('utf-8')).hexdigest()
    
    def _encode_sha256(self, data: str) -> str:
        """SHA256哈希"""
        return hashlib.sha256(data.encode('utf-8')).hexdigest()
    
    # ========== 自动检测方法 ==========
    
    def _detect_base64(self, data: str) -> float:
        """检测Base64编码"""
        # Base64特征：只包含A-Za-z0-9+/=，长度是4的倍数
        base64_pattern = r'^[A-Za-z0-9+/]*={0,2}$'
        
        if re.match(base64_pattern, data):
            # 检查长度
            if len(data) % 4 == 0:
                # 尝试解码验证
                try:
                    self._decode_base64(data)
                    return 0.9
                except:
                    return 0.3
            else:
                return 0.2
        else:
            return 0.0
    
    def _detect_url(self, data: str) -> float:
        """检测URL编码"""
        # URL编码特征：包含%后跟两个十六进制数字
        url_pattern = r'%[0-9a-fA-F]{2}'
        
        matches = re.findall(url_pattern, data)
        if matches:
            # 计算URL编码字符的比例
            url_chars = len(''.join(matches))
            total_chars = len(data)
            ratio = url_chars / total_chars if total_chars > 0 else 0
            
            if ratio > 0.1:  # 至少10%的字符是URL编码
                # 尝试解码验证
                try:
                    decoded = self._decode_url(data)
                    # 如果解码后包含可打印字符，置信度更高
                    if any(c.isprintable() for c in decoded):
                        return min(ratio * 2, 0.8)
                    else:
                        return ratio
                except:
                    return ratio * 0.5
        
        return 0.0
    
    def _detect_html(self, data: str) -> float:
        """检测HTML编码"""
        # HTML编码特征：包含&后跟字母或#数字;
        html_pattern = r'&(?:[a-zA-Z]+|#\d+);'
        
        matches = re.findall(html_pattern, data)
        if matches:
            # 计算HTML实体字符的比例
            html_chars = len(''.join(matches))
            total_chars = len(data)
            ratio = html_chars / total_chars if total_chars > 0 else 0
            
            if ratio > 0.05:  # 至少5%的字符是HTML实体
                # 尝试解码验证
                try:
                    decoded = self._decode_html(data)
                    if decoded != data:  # 解码后有变化
                        return min(ratio * 3, 0.7)
                    else:
                        return ratio
                except:
                    return ratio * 0.5
        
        return 0.0
    
    def _detect_hex(self, data: str) -> float:
        """检测Hex编码"""
        # Hex编码特征：只包含0-9a-fA-F，长度是偶数
        hex_pattern = r'^[0-9a-fA-F]+$'
        
        if re.match(hex_pattern, data) and len(data) % 2 == 0:
            # 尝试解码验证
            try:
                self._decode_hex(data)
                return 0.8
            except:
                return 0.2
        else:
            return 0.0
    
    # ========== 高级功能方法 ==========
    
    def chain_encode(self, data: str, encoding_chain: List[EncodingType]) -> EncodingResult:
        """链式编码"""
        current_data = data
        
        for encoding_type in encoding_chain:
            result = self.encode(current_data, encoding_type)
            current_data = result.output_data
        
        final_result = EncodingResult(
            input_data=data,
            output_data=current_data,
            encoding_type=EncodingType.CUSTOM,
            operation="chain_encode",
            timestamp=datetime.now()
        )
        
        self.encoding_history.append(final_result)
        return final_result
    
    def chain_decode(self, data: str, decoding_chain: List[EncodingType]) -> EncodingResult:
        """链式解码"""
        current_data = data
        
        for encoding_type in reversed(decoding_chain):
            result = self.decode(current_data, encoding_type)
            current_data = result.output_data
        
        final_result = EncodingResult(
            input_data=data,
            output_data=current_data,
            encoding_type=EncodingType.CUSTOM,
            operation="chain_decode",
            timestamp=datetime.now()
        )
        
        self.encoding_history.append(final_result)
        return final_result
    
    def smart_decode(self, data: str, max_depth: int = 3) -> List[EncodingResult]:
        """智能解码（尝试多种解码方式）"""
        results = []
        
        def try_decode(current_data: str, path: List[EncodingType], depth: int):
            if depth >= max_depth:
                return
            
            # 检测可能的编码类型
            detected_types = self.auto_detect(current_data)
            
            for encoding_type, confidence in detected_types:
                if confidence > 0.3:  # 置信度阈值
                    try:
                        result = self.decode(current_data, encoding_type)
                        
                        # 记录解码路径
                        result_path = path + [encoding_type]
                        result.operation = f"smart_decode: {' -> '.join(et.value for et in result_path)}"
                        
                        results.append(result)
                        
                        # 递归尝试进一步解码
                        try_decode(result.output_data, result_path, depth + 1)
                        
                    except:
                        continue
        
        try_decode(data, [], 0)
        return results
    
    def register_custom_encoder(self, name: str, encode_func: Callable, decode_func: Callable = None):
        """注册自定义编码器"""
        self.encoders[name] = encode_func
        
        if decode_func:
            self.decoders[name] = decode_func
        
        self.custom_rules[name] = (encode_func, decode_func)
        logger.info(f"注册自定义编码器: {name}")
    
    def unregister_custom_encoder(self, name: str):
        """注销自定义编码器"""
        if name in self.encoders:
            del self.encoders[name]
        
        if name in self.decoders:
            del self.decoders[name]
        
        if name in self.custom_rules:
            del self.custom_rules[name]
        
        logger.info(f"注销自定义编码器: {name}")
    
    # ========== 实用工具方法 ==========
    
    def compare_encodings(self, data: str, encoding_types: List[EncodingType]) -> Dict[str, str]:
        """比较不同编码方式的结果"""
        comparison = {}
        
        for encoding_type in encoding_types:
            try:
                if encoding_type.value in self.encoders:
                    encoded = self.encoders[encoding_type.value](data)
                    comparison[encoding_type.value] = encoded
            except Exception as e:
                comparison[encoding_type.value] = f"错误: {str(e)}"
        
        return comparison
    
    def generate_encoding_table(self, data: str) -> List[Dict[str, str]]:
        """生成编码对照表"""
        table = []
        
        for encoding_type in EncodingType:
            if encoding_type != EncodingType.CUSTOM:
                try:
                    if encoding_type.value in self.encoders:
                        encoded = self.encoders[encoding_type.value](data)
                        
                        table.append({
                            'encoding_type': encoding_type.value,
                            'encoded_data': encoded,
                            'length': len(encoded),
                            'status': '成功'
                        })
                    else:
                        table.append({
                            'encoding_type': encoding_type.value,
                            'encoded_data': '不支持编码',
                            'length': 0,
                            'status': '不支持'
                        })
                except Exception as e:
                    table.append({
                        'encoding_type': encoding_type.value,
                        'encoded_data': f"错误: {str(e)}",
                        'length': 0,
                        'status': '失败'
                    })
        
        return table
    
    def export_history(self, format: str = "json") -> str:
        """导出编码历史"""
        if format == "json":
            import json
            return json.dumps([r.to_dict() for r in self.encoding_history], indent=2, ensure_ascii=False)
        
        elif format == "csv":
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.writer(output)
            
            # 写入表头
            writer.writerow(["时间", "操作", "编码类型", "输入数据", "输出数据"])
            
            # 写入数据
            for result in self.encoding_history:
                writer.writerow([
                    result.timestamp.isoformat(),
                    result.operation,
                    result.encoding_type.value,
                    result.input_data,
                    result.output_data
                ])
            
            return output.getvalue()
        
        else:
            raise ValueError(f"不支持的导出格式: {format}")
    
    # ========== 公共方法 ==========
    
    def get_supported_encodings(self) -> List[str]:
        """获取支持的编码类型"""
        return list(self.encoders.keys())
    
    def get_supported_decodings(self) -> List[str]:
        """获取支持的解码类型"""
        return list(self.decoders.keys())
    
    def get_encoding_history(self, limit: int = 100) -> List[EncodingResult]:
        """获取编码历史"""
        return self.encoding_history[-limit:] if self.encoding_history else []
    
    def clear_history(self):
        """清空历史记录"""
        self.encoding_history.clear()
        logger.info("编码历史已清空")
    
    def get_custom_rules(self) -> Dict[str, Tuple[Callable, Optional[Callable]]]:
        """获取自定义规则"""
        return self.custom_rules.copy()

# 编码管理器
class EncodingManager:
    """编码管理器"""
    
    def __init__(self):
        self.encoders: Dict[str, AdvancedEncoderDecoder] = {}
    
    def create_encoder(self, encoder_id: str) -> AdvancedEncoderDecoder:
        """创建编码器实例"""
        encoder = AdvancedEncoderDecoder()
        self.encoders[encoder_id] = encoder
        return encoder
    
    def get_encoder(self, encoder_id: str) -> Optional[AdvancedEncoderDecoder]:
        """获取编码器"""
        return self.encoders.get(encoder_id)
    
    def get_all_encoders(self) -> Dict[str, AdvancedEncoderDecoder]:
        """获取所有编码器"""
        return self.encoders.copy()
    
    def batch_encode_all(self, data_list: List[str], encoding_type: EncodingType) -> Dict[str, List[EncodingResult]]:
        """使用所有编码器批量编码"""
        results = {}
        
        for encoder_id, encoder in self.encoders.items():
            try:
                encoder_results = encoder.batch_process(data_list, "encode", encoding_type)
                results[encoder_id] = encoder_results
            except Exception as e:
                results[encoder_id] = [f"错误: {str(e)}"]
        
        return results