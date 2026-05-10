"""
安全知识库系统 - 专家级升级版
基于360 CNVD与字节跳动SRC安全专家20年经验
昆仑安全实验室 - 荣誉出品
"""

import logging
import json
import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


class KnowledgeItem:
    """知识条目 - 增强版"""
    
    def __init__(
        self,
        id: str,
        title: str,
        category: str,
        content: str,
        author: str,
        tags: List[str] = None,
        rating: int = 0,
        difficulty: str = "入门",
        created_at: str = None,
        updated_at: str = None,
        status: str = "已发布",
        summary: str = ""
    ):
        self.id = id
        self.title = title
        self.category = category
        self.content = content
        self.author = author
        self.tags = tags or []
        self.rating = rating
        self.difficulty = difficulty
        self.created_at = created_at or datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.updated_at = updated_at or datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.status = status
        self.summary = summary
        self.views = 0
        self.likes = 0
        self.related_items = []
        self.bookmark = False
        self.progress = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "content": self.content,
            "author": self.author,
            "tags": self.tags,
            "rating": self.rating,
            "difficulty": self.difficulty,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "status": self.status,
            "summary": self.summary,
            "views": self.views,
            "likes": self.likes,
            "related_items": self.related_items,
            "bookmark": self.bookmark,
            "progress": self.progress
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'KnowledgeItem':
        """从字典创建"""
        item = cls(
            id=data["id"],
            title=data["title"],
            category=data["category"],
            content=data["content"],
            author=data["author"],
            tags=data.get("tags", []),
            rating=data.get("rating", 0),
            difficulty=data.get("difficulty", "入门"),
            created_at=data.get("created_at"),
            updated_at=data.get("updated_at"),
            status=data.get("status", "已发布"),
            summary=data.get("summary", "")
        )
        item.views = data.get("views", 0)
        item.likes = data.get("likes", 0)
        item.related_items = data.get("related_items", [])
        item.bookmark = data.get("bookmark", False)
        item.progress = data.get("progress", 0)
        return item


class KnowledgeBase:
    """知识库管理器 - 专家级升级版"""
    
    CATEGORIES = [
        "漏洞情报",
        "攻击技术",
        "防御方案",
        "安全标准",
        "工具使用",
        "最佳实践",
        "案例分析",
        "高级技术",
        "红蓝对抗"
    ]
    
    DIFFICULTIES = ["入门", "进阶", "高级", "专家"]
    
    def __init__(self, base_path: str = "data/knowledge"):
        self.base_path = Path(base_path)
        self.base_path.mkdir(parents=True, exist_ok=True)
        
        self.items: Dict[str, KnowledgeItem] = {}
        self._load_knowledge_base()
    
    def _load_knowledge_base(self):
        """加载知识库"""
        try:
            index_file = self.base_path / "index.json"
            if index_file.exists():
                with open(index_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for item_data in data.values():
                        item = KnowledgeItem.from_dict(item_data)
                        self.items[item.id] = item
            else:
                self._init_expert_knowledge()
        except Exception as e:
            logger.error(f"加载知识库失败: {e}")
            self._init_expert_knowledge()
    
    def _init_expert_knowledge(self):
        """初始化专家级知识库"""
        expert_items = self._get_expert_knowledge_items()
        
        for item_data in expert_items:
            item = KnowledgeItem.from_dict(item_data)
            self.items[item.id] = item
        
        self._save_index()
        logger.info(f"专家级知识库初始化完成，共 {len(expert_items)} 篇知识")
    
    def _get_expert_knowledge_items(self) -> List[Dict[str, Any]]:
        """获取专家级知识条目"""
        return [
            {
                "id": "k001",
                "title": "SQL注入攻击原理与防御 - 专家级",
                "category": "攻击技术",
                "difficulty": "高级",
                "summary": "深入剖析SQL注入的各类变体、绕过技术、高级利用技巧以及对应的防御方案",
                "content": """
<h2>SQL注入攻击原理 - 专家级</h2>
<p>SQL注入是一种代码注入技术，攻击者通过在应用程序的输入中插入恶意SQL代码来操纵数据库。</p>

<h3>攻击类型详解</h3>
<ul>
    <li><strong>布尔盲注</strong> - 通过页面响应的真假来推断信息</li>
    <li><strong>时间盲注</strong> - 通过响应时间的差异来推断信息</li>
    <li><strong>错误回显</strong> - 利用数据库错误信息获取数据</li>
    <li><strong>UNION查询</strong> - 合并查询结果</li>
    <li><strong>堆叠查询</strong> - 执行多条SQL语句</li>
    <li><strong>二次注入</strong> - 数据存储后触发的注入</li>
    <li><strong>宽字节注入</strong> - 字符编码问题导致的注入</li>
</ul>

<h3>高级绕过技术</h3>
<ul>
    <li>注释符绕过（/**/、--、#）</li>
    <li>大小写绕过</li>
    <li>编码绕过（Hex、URL、Unicode）</li>
    <li>等价函数替换</li>
    <li>WAF绕过技巧</li>
</ul>

<h3>数据库特定技巧</h3>
<h4>MySQL</h4>
<ul>
    <li>LOAD_FILE读取文件</li>
    <li>INTO OUTFILE写入文件</li>
    <li>存储过程利用</li>
</ul>

<h4>MSSQL</h4>
<ul>
    <li>xp_cmdshell执行命令</li>
    <li>sp_oacreate执行任意命令</li>
    <li>OPENROWSET读取文件</li>
</ul>

<h4>PostgreSQL</h4>
<ul>
    <li>COPY FROM读取文件</li>
    <li>COPY TO写入文件</li>
    <li>lo_import大对象注入</li>
</ul>

<h3>防御措施</h3>
<ul>
    <li>使用参数化查询（预编译语句）</li>
    <li>输入验证和白名单过滤</li>
    <li>最小权限原则</li>
    <li>使用ORM框架</li>
    <li>部署WAF</li>
    <li>数据库加固</li>
</ul>
                """,
                "author": "昆仑安全实验室",
                "tags": ["SQL注入", "Web安全", "攻击技术", "防御", "专家级"],
                "rating": 5,
                "status": "已发布"
            },
            {
                "id": "k002",
                "title": "XSS跨站脚本攻击详解 - 专家级",
                "category": "攻击技术",
                "difficulty": "高级",
                "summary": "全面讲解XSS的各种变体、绕过技术、高级利用以及完整的防御方案",
                "content": """
<h2>XSS攻击概述 - 专家级</h2>
<p>跨站脚本攻击（XSS）是一种在Web应用中注入恶意脚本的安全漏洞。</p>

<h3>攻击类型详解</h3>
<ul>
    <li><strong>反射型XSS</strong> - 脚本在URL中，服务器反射回页面</li>
    <li><strong>存储型XSS</strong> - 脚本存储在服务器数据库中</li>
    <li><strong>DOM型XSS</strong> - 脚本在客户端DOM中执行</li>
    <li><strong>MXSS</strong> - 突变型XSS</li>
    <li><strong>UXSS</strong> - 通用型XSS</li>
</ul>

<h3>高级绕过技术</h3>
<ul>
    <li>标签过滤绕过</li>
    <li>事件处理器绕过</li>
    <li>JavaScript编码绕过</li>
    <li>SVG/XML XSS</li>
    <li>CSS注入XSS</li>
</ul>

<h3>高级利用技巧</h3>
<ul>
    <li>Cookie窃取与session劫持</li>
    <li>钓鱼攻击</li>
    <li>键盘记录</li>
    <li>浏览器指纹</li>
    <li>内网探测</li>
</ul>

<h3>防御方法</h3>
<ul>
    <li>输出编码（HTML、JS、URL、CSS）</li>
    <li>Content Security Policy (CSP)</li>
    <li>HttpOnly Cookie</li>
    <li>输入验证</li>
    <li>X-XSS-Protection头</li>
</ul>
                """,
                "author": "昆仑安全实验室",
                "tags": ["XSS", "跨站脚本", "Web安全", "专家级"],
                "rating": 5,
                "status": "已发布"
            },
            {
                "id": "k003",
                "title": "OWASP Top 10 2021 深度解读",
                "category": "安全标准",
                "difficulty": "进阶",
                "summary": "对OWASP Top 10 2021的每一项进行深入分析，包含攻击原理、检测方法和防御方案",
                "content": """
<h2>OWASP Top 10 2021 - 专家级解读</h2>
<p>OWASP Top 10是最关键的Web应用程序安全风险列表。</p>

<h3>2021版Top 10 深度解析</h3>
<ol>
    <li>
        <strong>A01:2021 - 访问控制失效</strong>
        <ul>
            <li>越权访问（水平/垂直）</li>
            <li>IDOR漏洞</li>
            <li>未授权功能访问</li>
            <li>防御方案</li>
        </ul>
    </li>
    <li>
        <strong>A02:2021 - 加密失效</strong>
        <ul>
            <li>敏感数据明文传输</li>
            <li>弱加密算法</li>
            <li>硬编码密钥</li>
            <li>防御方案</li>
        </ul>
    </li>
    <li>
        <strong>A03:2021 - 注入</strong>
        <ul>
            <li>SQL注入</li>
            <li>NoSQL注入</li>
            <li>命令注入</li>
            <li>防御方案</li>
        </ul>
    </li>
    <li>
        <strong>A04:2021 - 不安全设计</strong>
        <ul>
            <li>威胁建模缺失</li>
            <li>安全需求不明确</li>
            <li>防御方案</li>
        </ul>
    </li>
    <li>
        <strong>A05:2021 - 安全配置错误</strong>
        <ul>
            <li>默认密码</li>
            <li>调试信息泄露</li>
            <li>不必要功能开启</li>
            <li>防御方案</li>
        </ul>
    </li>
    <li>
        <strong>A06:2021 - 易受攻击和过时的组件</strong>
        <ul>
            <li>已知漏洞利用</li>
            <li>供应链攻击</li>
            <li>防御方案</li>
        </ul>
    </li>
    <li>
        <strong>A07:2021 - 识别和认证失效</strong>
        <ul>
            <li>凭据管理不当</li>
            <li>会话固定</li>
            <li>暴力破解</li>
            <li>防御方案</li>
        </ul>
    </li>
    <li>
        <strong>A08:2021 - 软件和数据完整性失效</strong>
        <ul>
            <li>不安全的更新</li>
            <li>CI/CD安全问题</li>
            <li>防御方案</li>
        </ul>
    </li>
    <li>
        <strong>A09:2021 - 安全日志和监控失效</strong>
        <ul>
            <li>日志不足</li>
            <li>监控缺失</li>
            <li>响应不当</li>
            <li>防御方案</li>
        </ul>
    </li>
    <li>
        <strong>A10:2021 - 服务端请求伪造 (SSRF)</strong>
        <ul>
            <li>SSRF攻击原理</li>
            <li>绕过技术</li>
            <li>防御方案</li>
        </ul>
    </li>
</ol>
                """,
                "author": "昆仑安全实验室",
                "tags": ["OWASP", "安全标准", "Top 10", "专家级"],
                "rating": 5,
                "status": "已发布"
            },
            {
                "id": "k004",
                "title": "Burp Suite 高级使用指南",
                "category": "工具使用",
                "difficulty": "高级",
                "summary": "Burp Suite的高级使用技巧，包括扩展开发、自动化测试、团队协作等",
                "content": """
<h2>Burp Suite 高级使用指南</h2>
<p>Burp Suite是Web应用安全测试的行业标准工具集。</p>

<h3>核心组件深度解析</h3>
<ul>
    <li><strong>Proxy</strong> - 拦截和修改HTTP/HTTPS流量、匹配和替换规则</li>
    <li><strong>Scanner</strong> - 自动漏洞扫描、主动/被动扫描、扫描配置</li>
    <li><strong>Intruder</strong> - 自动化攻击、攻击类型（Sniper/Battering Ram/Pitchfork/Cluster Bomb）、Payload处理</li>
    <li><strong>Repeater</strong> - 手动测试和重放请求、分组管理</li>
    <li><strong>Sequencer</strong> - 分析会话令牌随机性、熵分析</li>
    <li><strong>Decoder</strong> - 编码解码、智能解码</li>
    <li><strong>Comparer</strong> - 对比数据、字节级差异</li>
    <li><strong>Extender</strong> - 扩展插件、BApp Store</li>
</ul>

<h3>高级功能</h3>
<ul>
    <li>Session Handling规则配置</li>
    <li>Macro功能</li>
    <li>项目配置和恢复</li>
    <li>Collaborator OOB测试</li>
</ul>

<h3>扩展开发</h3>
<ul>
    <li>Montoya API介绍</li>
    <li>Python/Java扩展开发</li>
    <li>常用扩展推荐</li>
</ul>

<h3>工作流程优化</h3>
<ol>
    <li>配置浏览器代理</li>
    <li>流量通过Proxy</li>
    <li>使用Repeater测试</li>
    <li>使用Intruder自动化</li>
    <li>使用Scanner辅助</li>
    <li>生成报告</li>
</ol>
                """,
                "author": "昆仑安全实验室",
                "tags": ["Burp Suite", "安全工具", "Web测试", "高级"],
                "rating": 5,
                "status": "已发布"
            },
            {
                "id": "k005",
                "title": "渗透测试方法论 - 20年经验总结",
                "category": "最佳实践",
                "difficulty": "专家",
                "summary": "基于20年渗透测试经验总结的完整方法论，从信息收集到报告撰写",
                "content": """
<h2>渗透测试方法论 - 专家级</h2>
<p>基于20年渗透测试经验总结的完整方法论。</p>

<h3>测试流程</h3>
<ol>
    <li><strong>前期交互</strong> - 合同签署、范围确定、规则约定</li>
    <li><strong>情报收集</strong> - OSINT、被动侦察、主动侦察</li>
    <li><strong>威胁建模</strong> - 资产识别、漏洞分析、风险评估</li>
    <li><strong>漏洞分析</strong> - 漏洞验证、影响评估</li>
    <li><strong>漏洞利用</strong> - 权限提升、横向移动</li>
    <li><strong>后渗透</strong> - 持久化、数据窃取、痕迹清除</li>
    <li><strong>报告撰写</strong> - 漏洞报告、修复建议</li>
</ol>

<h3>信息收集技术</h3>
<ul>
    <li>域名信息收集（WHOIS、DNS、子域名枚举）</li>
    <li>网络信息收集（端口扫描、服务识别）</li>
    <li>Web信息收集（爬虫、指纹识别）</li>
    <li>社会工程学信息</li>
</ul>

<h3>漏洞分析方法</h3>
<ul>
    <li>手工测试方法</li>
    <li>自动化扫描工具</li>
    <li>漏洞验证流程</li>
</ul>

<h3>专业报告撰写</h3>
<ul>
    <li>报告结构</li>
    <li>风险评级方法</li>
    <li>修复建议标准</li>
</ul>
                """,
                "author": "昆仑安全实验室",
                "tags": ["渗透测试", "方法论", "最佳实践", "专家级"],
                "rating": 5,
                "status": "已发布"
            },
            {
                "id": "k006",
                "title": "命令注入攻击与防御",
                "category": "攻击技术",
                "difficulty": "进阶",
                "summary": "命令注入的原理、绕过技术、利用方法和完整的防御方案",
                "content": """
<h2>命令注入攻击与防御</h2>
<p>命令注入是一种严重的安全漏洞，允许攻击者在目标系统上执行任意命令。</p>

<h3>攻击原理</h3>
<ul>
    <li>命令分隔符（;、&、&&、||）</li>
    <li>管道命令（|）</li>
    <li>重定向（>、>>、<）</li>
    <li>子shell执行（`、$()）</li>
</ul>

<h3>绕过技术</h3>
<ul>
    <li>空格绕过（${IFS}、$IFS$9、{cat,file}）</li>
    <li>通配符绕过</li>
    <li>编码绕过（Hex、Oct、Base64）</li>
    <li>长度限制绕过</li>
</ul>

<h3>高级利用</h3>
<ul>
    <li>Shell反弹</li>
    <li>权限提升</li>
    <li>内网探测</li>
    <li>持久化</li>
</ul>

<h3>防御方案</h3>
<ul>
    <li>避免使用系统命令</li>
    <li>使用安全API</li>
    <li>输入白名单验证</li>
    <li>最小权限原则</li>
</ul>
                """,
                "author": "昆仑安全实验室",
                "tags": ["命令注入", "RCE", "Web安全", "攻击技术"],
                "rating": 5,
                "status": "已发布"
            },
            {
                "id": "k007",
                "title": "SSRF攻击与防御 - 专家级",
                "category": "攻击技术",
                "difficulty": "高级",
                "summary": "SSRF攻击的原理、绕过技术、利用方法和完整的防御方案",
                "content": """
<h2>SSRF攻击与防御 - 专家级</h2>
<p>服务端请求伪造（SSRF）是一种允许攻击者伪造服务端发起请求的安全漏洞。</p>

<h3>攻击原理</h3>
<ul>
    <li>服务端发起请求的功能</li>
    <li>URL/地址可控</li>
    <li>响应信息可利用</li>
</ul>

<h3>攻击类型</h3>
<ul>
    <li>内网探测</li>
    <li>端口扫描</li>
    <li>本地文件读取（file://）</li>
    <li>云服务元数据读取</li>
    <li>Redis未授权访问利用</li>
</ul>

<h3>绕过技术</h3>
<ul>
    <li>@符号绕过</li>
    <li>IP进制转换（八进制、十六进制、十进制）</li>
    <li>DNS重绑定</li>
    <li>URL重定向</li>
    <li>协议混淆（http://、dict://、gopher://）</li>
</ul>

<h3>防御方案</h3>
<ul>
    <li>白名单机制</li>
    <li>协议限制</li>
    <li>禁用跳转</li>
    <li>网络隔离</li>
</ul>
                """,
                "author": "昆仑安全实验室",
                "tags": ["SSRF", "Web安全", "攻击技术", "专家级"],
                "rating": 5,
                "status": "已发布"
            },
            {
                "id": "k008",
                "title": "Web安全防御最佳实践",
                "category": "防御方案",
                "difficulty": "进阶",
                "summary": "Web应用安全的完整防御方案，从开发到部署的全过程安全",
                "content": """
<h2>Web安全防御最佳实践</h2>
<p>Web应用安全的完整防御方案。</p>

<h3>安全开发生命周期</h3>
<ul>
    <li>需求阶段 - 安全需求分析</li>
    <li>设计阶段 - 威胁建模</li>
    <li>实现阶段 - 安全编码</li>
    <li>测试阶段 - 安全测试</li>
    <li>部署阶段 - 安全配置</li>
</ul>

<h3>安全配置</h3>
<ul>
    <li>HTTP安全头（CSP、X-Frame-Options、X-XSS-Protection等）</li>
    <li>HTTPS配置</li>
    <li>Session安全</li>
    <li>Cookie安全（HttpOnly、Secure、SameSite）</li>
</ul>

<h3>常见漏洞防御</h3>
<ul>
    <li>SQL注入防御</li>
    <li>XSS防御</li>
    <li>CSRF防御</li>
    <li>SSRF防御</li>
</ul>

<h3>DevSecOps实践</h3>
<ul>
    <li>自动化安全测试</li>
    <li>SAST/DAST/IAST工具集成</li>
    <li>容器安全</li>
</ul>
                """,
                "author": "昆仑安全实验室",
                "tags": ["Web安全", "防御方案", "最佳实践"],
                "rating": 5,
                "status": "已发布"
            },
            {
                "id": "k009",
                "title": "红队实战技术指南",
                "category": "红蓝对抗",
                "difficulty": "专家",
                "summary": "红队实战的完整技术体系，包括情报收集、初始访问、横向移动等",
                "content": """
<h2>红队实战技术指南</h2>
<p>红队实战的完整技术体系。</p>

<h3>红队作战流程</h3>
<ol>
    <li><strong>情报收集</strong> - OSINT、被动侦察</li>
    <li><strong>初始访问</strong> - 钓鱼、供应链、外部漏洞</li>
    <li><strong>持久化</strong> - 建立后门、权限维持</li>
    <li><strong>权限提升</strong> - 本地提权、域提权</li>
    <li><strong>横向移动</strong> - 凭据窃取、远程访问</li>
    <li><strong>目标访问</strong> - 关键资产访问</li>
    <li><strong>影响</strong> - 数据窃取、系统破坏</li>
</ol>

<h3>关键技术</h3>
<ul>
    <li>钓鱼邮件技术</li>
    <li>横向移动技术</li>
    <li>权限提升技术</li>
    <li>持久化技术</li>
    <li>免杀技术</li>
</ul>

<h3>常用工具</h3>
<ul>
    <li>Cobalt Strike</li>
    <li>Empire</li>
    <li>Metasploit</li>
    <li>BloodHound</li>
</ul>
                """,
                "author": "昆仑安全实验室",
                "tags": ["红队", "红蓝对抗", "渗透测试", "专家级"],
                "rating": 5,
                "status": "已发布"
            },
            {
                "id": "k010",
                "title": "高级持续威胁（APT）分析与防御",
                "category": "高级技术",
                "difficulty": "专家",
                "summary": "APT攻击的特征、生命周期、常用技术以及完整的防御方案",
                "content": """
<h2>高级持续威胁（APT）分析与防御</h2>
<p>APT攻击是一种有组织、有目的的网络攻击。</p>

<h3>APT特征</h3>
<ul>
    <li>目标明确</li>
    <li>持续时间长</li>
    <li>技术手段先进</li>
    <li>隐蔽性强</li>
</ul>

<h3>APT生命周期</h3>
<ol>
    <li>侦察</li>
    <li>武器化</li>
    <li>投递</li>
    <li>利用</li>
    <li>安装</li>
    <li>命令与控制</li>
    <li>目标行动</li>
</ol>

<h3>常用技术</h3>
<ul>
    <li>0day漏洞利用</li>
    <li>定制恶意代码</li>
    <li>合法工具滥用</li>
    <li>文件less攻击</li>
</ul>

<h3>防御方案</h3>
<ul>
    <li>威胁情报</li>
    <li>异常检测</li>
    <li>终端检测与响应（EDR）</li>
    <li>网络流量分析</li>
</ul>
                """,
                "author": "昆仑安全实验室",
                "tags": ["APT", "高级技术", "威胁情报", "防御", "专家级"],
                "rating": 5,
                "status": "已发布"
            }
        ]
    
    def _save_index(self):
        """保存索引"""
        try:
            data = {k: v.to_dict() for k, v in self.items.items()}
            with open(self.base_path / "index.json", "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"保存知识库索引失败: {e}")
    
    def add_item(self, item: KnowledgeItem) -> str:
        """添加知识条目"""
        self.items[item.id] = item
        self._save_index()
        logger.info(f"添加知识条目: {item.title}")
        return item.id
    
    def get_item(self, item_id: str) -> Optional[KnowledgeItem]:
        """获取知识条目"""
        item = self.items.get(item_id)
        if item:
            item.views += 1
            self._save_index()
        return item
    
    def update_item(self, item_id: str, updates: Dict[str, Any]) -> bool:
        """更新知识条目"""
        if item_id in self.items:
            item = self.items[item_id]
            for key, value in updates.items():
                if hasattr(item, key):
                    setattr(item, key, value)
            item.updated_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self._save_index()
            logger.info(f"更新知识条目: {item_id}")
            return True
        return False
    
    def delete_item(self, item_id: str) -> bool:
        """删除知识条目"""
        if item_id in self.items:
            del self.items[item_id]
            self._save_index()
            logger.info(f"删除知识条目: {item_id}")
            return True
        return False
    
    def search_items(
        self,
        keyword: str = "",
        category: str = "",
        tags: List[str] = None,
        difficulty: str = ""
    ) -> List[KnowledgeItem]:
        """搜索知识条目"""
        results = []
        
        for item in self.items.values():
            match = True
            
            if keyword:
                keyword_lower = keyword.lower()
                if (keyword_lower not in item.title.lower() and
                    keyword_lower not in item.content.lower() and
                    not any(keyword_lower in tag.lower() for tag in item.tags)):
                    match = False
            
            if category and category != "全部" and item.category != category:
                match = False
            
            if tags:
                if not any(tag in item.tags for tag in tags):
                    match = False
            
            if difficulty and difficulty != "全部" and item.difficulty != difficulty:
                match = False
            
            if match:
                results.append(item)
        
        return results
    
    def get_items_by_category(self, category: str) -> List[KnowledgeItem]:
        """按分类获取知识条目"""
        return [item for item in self.items.values() if item.category == category]
    
    def get_all_items(self) -> List[KnowledgeItem]:
        """获取所有知识条目"""
        return list(self.items.values())
    
    def get_recent_items(self, limit: int = 10) -> List[KnowledgeItem]:
        """获取最近更新的知识条目"""
        items = sorted(self.items.values(), key=lambda x: x.updated_at, reverse=True)
        return items[:limit]
    
    def get_popular_items(self, limit: int = 10) -> List[KnowledgeItem]:
        """获取热门知识条目"""
        items = sorted(self.items.values(), key=lambda x: x.views, reverse=True)
        return items[:limit]
    
    def get_bookmarked_items(self) -> List[KnowledgeItem]:
        """获取收藏的知识条目"""
        return [item for item in self.items.values() if item.bookmark]
    
    def like_item(self, item_id: str) -> bool:
        """点赞知识条目"""
        item = self.items.get(item_id)
        if item:
            item.likes += 1
            self._save_index()
            return True
        return False
    
    def toggle_bookmark(self, item_id: str) -> bool:
        """切换收藏状态"""
        item = self.items.get(item_id)
        if item:
            item.bookmark = not item.bookmark
            self._save_index()
            return True
        return False
    
    def set_progress(self, item_id: str, progress: int) -> bool:
        """设置阅读进度"""
        item = self.items.get(item_id)
        if item:
            item.progress = min(max(progress, 0), 100)
            self._save_index()
            return True
        return False
    
    def add_related_item(self, item_id: str, related_id: str) -> bool:
        """添加关联知识条目"""
        item = self.items.get(item_id)
        if item and related_id in self.items:
            if related_id not in item.related_items:
                item.related_items.append(related_id)
                self._save_index()
            return True
        return False
    
    def get_related_items(self, item_id: str) -> List[KnowledgeItem]:
        """获取关联知识条目"""
        item = self.items.get(item_id)
        if item:
            return [self.items[rid] for rid in item.related_items if rid in self.items]
        return []


class KnowledgeRecommender:
    """知识推荐器"""
    
    def __init__(self, knowledge_base: KnowledgeBase):
        self.knowledge_base = knowledge_base
    
    def recommend_by_item(self, item: KnowledgeItem, limit: int = 5) -> List[KnowledgeItem]:
        """基于条目推荐"""
        candidates = []
        
        for other in self.knowledge_base.get_all_items():
            if other.id == item.id:
                continue
            
            score = 0
            if other.category == item.category:
                score += 3
            
            common_tags = set(other.tags) & set(item.tags)
            score += len(common_tags) * 2
            
            score += other.rating
            
            if score > 0:
                candidates.append((score, other))
        
        candidates.sort(key=lambda x: x[0], reverse=True)
        return [item for _, item in candidates[:limit]]
    
    def recommend_by_tags(self, tags: List[str], limit: int = 5) -> List[KnowledgeItem]:
        """基于标签推荐"""
        candidates = []
        
        for item in self.knowledge_base.get_all_items():
            common_tags = set(item.tags) & set(tags)
            if common_tags:
                score = len(common_tags) + item.rating
                candidates.append((score, item))
        
        candidates.sort(key=lambda x: x[0], reverse=True)
        return [item for _, item in candidates[:limit]]


logger.info("安全知识库系统 - 专家级升级版 初始化完成")
