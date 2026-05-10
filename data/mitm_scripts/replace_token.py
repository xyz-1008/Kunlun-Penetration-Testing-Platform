"""
模板：替换Token
自动替换请求中的认证Token
"""

class ScriptHook:
    def __init__(self):
        self.old_token = "old_token_here"
        self.new_token = "new_token_here"
    
    def on_request(self, request):
        # 替换Authorization Header
        if 'Authorization' in request.headers:
            auth = request.headers['Authorization']
            if self.old_token in auth:
                request.headers['Authorization'] = auth.replace(self.old_token, self.new_token)
        
        # 替换Body中的Token
        if request.body:
            body_str = request.body.decode('utf-8', errors='replace')
            if self.old_token in body_str:
                body_str = body_str.replace(self.old_token, self.new_token)
                request.body = body_str.encode('utf-8')
        
        return request
    
    def on_response(self, request, response):
        return response
