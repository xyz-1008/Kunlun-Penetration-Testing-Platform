"""
模板：日志上报
记录所有请求到文件
"""

import logging
from datetime import datetime

logger = logging.getLogger('mitm_script')

class ScriptHook:
    def __init__(self):
        self.log_file = "data/mitm_scripts/requests.log"
    
    def on_request(self, request):
        # 记录请求日志
        timestamp = datetime.utcnow().isoformat()
        log_line = f"[{timestamp}] {request.method} {request.url}\n"
        
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(log_line)
        except Exception as e:
            logger.error(f"写入日志失败: {e}")
        
        return request
    
    def on_response(self, request, response):
        # 记录响应日志
        timestamp = datetime.utcnow().isoformat()
        log_line = f"[{timestamp}] Response: {response.status_code} {request.url}\n"
        
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(log_line)
        except Exception as e:
            logger.error(f"写入日志失败: {e}")
        
        return response
