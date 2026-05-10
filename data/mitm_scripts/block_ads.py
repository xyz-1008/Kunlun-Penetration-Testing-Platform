"""
模板：广告拦截
拦截常见广告和跟踪请求
"""

import re

BLOCKED_DOMAINS = [
    'google-analytics.com',
    'doubleclick.net',
    'adservice.google.com',
    'facebook.com/tr',
    'analytics.twitter.com',
]

BLOCKED_PATHS = [
    '/ads/',
    '/analytics/',
    '/tracking/',
    '/pixel.',
]

class ScriptHook:
    def on_request(self, request):
        # 检查域名
        for domain in BLOCKED_DOMAINS:
            if domain in request.host:
                # 返回空响应拦截请求
                return self._create_block_response(request)
        
        # 检查路径
        for path in BLOCKED_PATHS:
            if path in request.path.lower():
                return self._create_block_response(request)
        
        return request
    
    def _create_block_response(self, request):
        """创建拦截响应"""
        class BlockedResponse:
            def __init__(self):
                self.id = request.id + '_blocked'
                self.request_id = request.id
                self.timestamp = request.timestamp
                self.status_code = 204
                self.reason = 'No Content'
                self.headers = {}
                self.body = b''
                self.content_type = ''
                self.content_length = 0
                self.response_time = 0.0
        
        return BlockedResponse()
    
    def on_response(self, request, response):
        return response
