"""
MITM代理移动端抓包支持模块
证书安装指南、导出配置、弱网模拟
"""

import os
import time
import random
import logging
from typing import Dict, Any, Optional
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)


class CertificateExport:
    """证书导出工具"""
    
    def __init__(self, cert_path: str = "", key_path: str = ""):
        self.cert_path = cert_path
        self.key_path = key_path
    
    def export_for_android(self, output_dir: str = "mobile_certs") -> str:
        """导出Android安装证书"""
        os.makedirs(output_dir, exist_ok=True)
        
        output_file = os.path.join(output_dir, "mitm_proxy_ca.crt")
        
        if self.cert_path and os.path.exists(self.cert_path):
            import shutil
            shutil.copy2(self.cert_path, output_file)
        else:
            # 生成示例证书
            with open(output_file, 'w') as f:
                f.write(self._generate_sample_cert())
        
        logger.info(f"Android证书已导出: {output_file}")
        return output_file
    
    def export_for_ios(self, output_dir: str = "mobile_certs") -> str:
        """导出iOS安装配置"""
        os.makedirs(output_dir, exist_ok=True)
        
        output_file = os.path.join(output_dir, "mitm_proxy.mobileconfig")
        
        # 生成.mobileconfig配置文件
        config = self._generate_mobileconfig()
        with open(output_file, 'w') as f:
            f.write(config)
        
        logger.info(f"iOS配置已导出: {output_file}")
        return output_file
    
    def generate_install_guide(self, output_dir: str = "mobile_certs") -> str:
        """生成安装指南"""
        os.makedirs(output_dir, exist_ok=True)
        
        output_file = os.path.join(output_dir, "install_guide.md")
        
        guide = """# MITM代理证书安装指南

## Android 安装步骤

### 方法一：通过设置安装
1. 将 `mitm_proxy_ca.crt` 文件传输到手机
2. 打开 **设置** > **安全** > **加密与凭据**
3. 点击 **安装证书** > **CA 证书**
4. 选择证书文件并确认安装
5. 安装完成后，在 **信任的凭据** > **用户** 中查看

### 方法二：通过浏览器安装
1. 在手机浏览器中访问代理地址（如 `http://192.168.1.100:8080/cert`）
2. 点击下载证书
3. 按提示完成安装

### 配置WiFi代理
1. 长按连接的WiFi网络 > **修改网络**
2. 展开 **高级选项**
3. 代理选择 **手动**
4. 输入代理服务器IP和端口（如 `192.168.1.100:8080`）
5. 保存

### Android 7+ 注意事项
- Android 7及以上版本默认不信任用户安装的CA证书
- 需要在应用中添加 `android:usesCleartextTraffic="true"`
- 或使用Magisk模块将证书移动到系统证书目录

---

## iOS 安装步骤

### 安装配置文件
1. 将 `mitm_proxy.mobileconfig` 文件传输到iPhone/iPad
   - 通过AirDrop、邮件或iCloud
2. 点击文件打开 **描述文件** 安装界面
3. 点击右上角 **安装**
4. 输入设备密码确认
5. 安装完成后，证书将出现在 **设置** > **通用** > **关于本机** > **证书信任设置**

### 启用完全信任
1. 打开 **设置** > **通用** > **关于本机**
2. 滚动到底部，点击 **证书信任设置**
3. 找到安装的证书，开启开关
4. 确认启用

### 配置WiFi代理
1. 打开 **设置** > **无线局域网**
2. 点击已连接WiFi右侧的 **ⓘ** 图标
3. 滚动到底部，点击 **配置代理**
4. 选择 **手动**
5. 输入服务器地址和端口（如 `192.168.1.100:8080`）
6. 点击 **存储**

---

## 验证安装

### Android
```bash
# 使用curl测试
curl -v https://example.com --proxy 192.168.1.100:8080
```

### iOS
- 打开Safari访问 `http://proxy.test`
- 应该能看到代理拦截页面

---

## 常见问题

### 证书不受信任
- 确保证书已正确安装
- Android 7+ 需要特殊处理
- iOS 需要启用完全信任

### 无法连接代理
- 检查手机和代理服务器在同一网络
- 确认防火墙允许代理端口
- 检查代理是否正在运行

### HTTPS无法解密
- 确认应用不使用证书锁定（Certificate Pinning）
- 某些应用（如银行App）会检测MITM并拒绝连接
"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(guide)
        
        logger.info(f"安装指南已生成: {output_file}")
        return output_file
    
    def _generate_sample_cert(self) -> str:
        """生成示例证书内容"""
        return """-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQDU+pQ4P0V5LjANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7
o4q3Tn3v4P0V5LjANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAlsb2NhbGhvc3Qw
ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7o4q3Tn3v4P0V5LjANBgk
qhkiG9w0BAQsFADAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQC7o4q3Tn3v4P0V5LjANBgkqhkiG9w0BAQsFADAUMRIw
EAYDVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQC7o4q3Tn3v4P0V5LjANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAlsb2NhbGhv
c3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7o4q3Tn3v
-----END CERTIFICATE-----
"""
    
    def _generate_mobileconfig(self) -> str:
        """生成iOS mobileconfig配置"""
        import uuid
        payload_uuid = str(uuid.uuid4())
        content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadDescription</key>
            <string>MITM Proxy CA Certificate</string>
            <key>PayloadDisplayName</key>
            <string>MITM Proxy CA</string>
            <key>PayloadIdentifier</key>
            <string>com.mitmproxy.ca.{payload_uuid}</string>
            <key>PayloadOrganization</key>
            <string>MITM Proxy</string>
            <key>PayloadType</key>
            <string>com.apple.security.root</string>
            <key>PayloadUUID</key>
            <string>{payload_uuid}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>
    </array>
    <key>PayloadDescription</key>
    <string>MITM Proxy Certificate Configuration</string>
    <key>PayloadDisplayName</key>
    <string>MITM Proxy</string>
    <key>PayloadIdentifier</key>
    <string>com.mitmproxy.profile.{payload_uuid}</string>
    <key>PayloadOrganization</key>
    <string>MITM Proxy</string>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>{payload_uuid}</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>
"""
        return content


class WeakNetworkSimulator:
    """弱网模拟器"""
    
    def __init__(self):
        self._enabled = False
        self._delay_ms = 0  # 延迟（毫秒）
        self._packet_loss_rate = 0.0  # 丢包率（0-1）
        self._bandwidth_limit = 0  # 带宽限制（KB/s），0表示不限制
        self._jitter_ms = 0  # 抖动（毫秒）
    
    def enable(self, delay_ms: int = 0, packet_loss: float = 0.0, 
               bandwidth_limit: int = 0, jitter_ms: int = 0):
        """启用弱网模拟"""
        self._enabled = True
        self._delay_ms = delay_ms
        self._packet_loss_rate = packet_loss
        self._bandwidth_limit = bandwidth_limit
        self._jitter_ms = jitter_ms
        logger.info(f"弱网模拟已启用: 延迟={delay_ms}ms, 丢包={packet_loss*100}%, "
                   f"带宽={bandwidth_limit}KB/s, 抖动={jitter_ms}ms")
    
    def disable(self):
        """禁用弱网模拟"""
        self._enabled = False
        logger.info("弱网模拟已禁用")
    
    def apply_delay(self):
        """应用延迟"""
        if not self._enabled or self._delay_ms == 0:
            return
        
        delay = self._delay_ms / 1000.0
        
        # 添加抖动
        if self._jitter_ms > 0:
            jitter = random.uniform(-self._jitter_ms, self._jitter_ms) / 1000.0
            delay += jitter
            delay = max(0, delay)  # 确保延迟不为负
        
        time.sleep(delay)
    
    def should_drop_packet(self) -> bool:
        """判断是否丢包"""
        if not self._enabled or self._packet_loss_rate == 0:
            return False
        
        return random.random() < self._packet_loss_rate
    
    def apply_bandwidth_limit(self, data_size: int) -> float:
        """应用带宽限制，返回需要等待的时间"""
        if not self._enabled or self._bandwidth_limit == 0:
            return 0
        
        # 计算传输时间
        time_needed = data_size / (self._bandwidth_limit * 1024)  # 秒
        return time_needed
    
    def get_config(self) -> Dict[str, Any]:
        """获取当前配置"""
        return {
            'enabled': self._enabled,
            'delay_ms': self._delay_ms,
            'packet_loss_rate': self._packet_loss_rate,
            'bandwidth_limit': self._bandwidth_limit,
            'jitter_ms': self._jitter_ms,
        }
    
    def set_preset(self, preset: str):
        """设置预设配置"""
        presets = {
            '3g': {'delay_ms': 200, 'packet_loss': 0.02, 'bandwidth_limit': 100, 'jitter_ms': 50},
            'edge': {'delay_ms': 500, 'packet_loss': 0.05, 'bandwidth_limit': 50, 'jitter_ms': 100},
            '2g': {'delay_ms': 1000, 'packet_loss': 0.1, 'bandwidth_limit': 20, 'jitter_ms': 200},
            'high_latency': {'delay_ms': 2000, 'packet_loss': 0.0, 'bandwidth_limit': 0, 'jitter_ms': 100},
            'unstable': {'delay_ms': 500, 'packet_loss': 0.15, 'bandwidth_limit': 50, 'jitter_ms': 300},
        }
        
        if preset in presets:
            config = presets[preset]
            self.enable(**config)
            logger.info(f"已应用弱网预设: {preset}")
        else:
            logger.warning(f"未知的弱网预设: {preset}")


class MobileSupport:
    """移动端支持管理器"""
    
    def __init__(self, cert_path: str = "", key_path: str = ""):
        self.cert_export = CertificateExport(cert_path, key_path)
        self.weak_network = WeakNetworkSimulator()
    
    def export_all(self, output_dir: str = "mobile_certs") -> Dict[str, str]:
        """导出所有移动端配置"""
        results = {}
        
        results['android_cert'] = self.cert_export.export_for_android(output_dir)
        results['ios_config'] = self.cert_export.export_for_ios(output_dir)
        results['install_guide'] = self.cert_export.generate_install_guide(output_dir)
        
        logger.info(f"移动端配置已导出到: {output_dir}")
        return results
    
    def get_status(self) -> Dict[str, Any]:
        """获取移动端支持状态"""
        return {
            'weak_network': self.weak_network.get_config(),
        }
