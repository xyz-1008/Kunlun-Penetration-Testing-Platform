"""
模板：自动添加Header
在每个请求中添加自定义Header
"""

class ScriptHook:
    def on_request(self, request):
        # 添加自定义Header
        request.headers['X-MITM-Proxy'] = 'AutoPenTest'
        request.headers['X-Forwarded-By'] = 'MITM-Module'
        return request
    
    def on_response(self, request, response):
        # 可以在这里修改响应
        return response
