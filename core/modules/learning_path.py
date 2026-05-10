"""Learning Path: Task-based learning paths, task definitions, and unlock logic.

Provides:
- Beginner, intermediate, and advanced learning paths
- Multiple challenge tasks per path: information gathering, vulnerability discovery, exploitation, lateral movement, persistence
- Natural language task descriptions with hints about what vulnerabilities to discover and what techniques to use
- Automatic task unlocking upon completion with completion time tracking
- Progressive hint system for beginners
- Answer reveal functionality with point cost or after multiple failed attempts
"""

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class PathDifficulty(Enum):
    """Learning path difficulty levels."""
    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"


class TaskCategory(Enum):
    """Task category types."""
    INFORMATION_GATHERING = "information_gathering"
    VULNERABILITY_DISCOVERY = "vulnerability_discovery"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    REPORTING = "reporting"


class TaskStatus(Enum):
    """Task completion status."""
    LOCKED = "locked"
    AVAILABLE = "available"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


class HintLevel(Enum):
    """Hint detail levels."""
    VAGUE = "vague"
    SPECIFIC = "specific"
    STEP_BY_STEP = "step_by_step"
    FULL_SOLUTION = "full_solution"


@dataclass
class Hint:
    """Progressive hint for task completion.

    Attributes:
        level: Hint detail level
        content: Hint content
        points_cost: Points required to reveal this hint
    """
    level: HintLevel = HintLevel.VAGUE
    content: str = ""
    points_cost: int = 0


@dataclass
class TaskDefinition:
    """Learning task definition.

    Attributes:
        task_id: Unique task identifier
        title: Task title
        description: Natural language task description
        category: Task category
        difficulty: Task difficulty
        range_id: Required range environment ID
        prerequisites: List of prerequisite task IDs
        objectives: List of task objectives
        hints: List of progressive hints
        full_solution: Complete solution with Kunlun module usage
        expected_flags: List of expected flags/proofs
        points_reward: Points awarded for completion
        estimated_time_minutes: Estimated completion time
        required_modules: List of Kunlun modules used
        mitre_techniques: List of MITRE ATT&CK technique IDs
        created_at: Task creation timestamp
    """
    task_id: str = ""
    title: str = ""
    description: str = ""
    category: TaskCategory = TaskCategory.INFORMATION_GATHERING
    difficulty: PathDifficulty = PathDifficulty.BEGINNER
    range_id: str = ""
    prerequisites: List[str] = field(default_factory=list)
    objectives: List[str] = field(default_factory=list)
    hints: List[Hint] = field(default_factory=list)
    full_solution: str = ""
    expected_flags: List[str] = field(default_factory=list)
    points_reward: int = 100
    estimated_time_minutes: int = 30
    required_modules: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    created_at: float = 0.0


@dataclass
class TaskProgress:
    """User task progress tracking.

    Attributes:
        task_id: Task identifier
        status: Current task status
        started_at: Task start time
        completed_at: Task completion time
        attempts: Number of attempts
        hints_used: List of hint levels used
        points_spent: Points spent on hints
        flags_found: List of flags found
        modules_used: List of modules used during task
        time_spent_seconds: Total time spent
        notes: User notes
    """
    task_id: str = ""
    status: TaskStatus = TaskStatus.LOCKED
    started_at: float = 0.0
    completed_at: float = 0.0
    attempts: int = 0
    hints_used: List[HintLevel] = field(default_factory=list)
    points_spent: int = 0
    flags_found: List[str] = field(default_factory=list)
    modules_used: List[str] = field(default_factory=list)
    time_spent_seconds: float = 0.0
    notes: str = ""


@dataclass
class LearningPath:
    """Complete learning path definition.

    Attributes:
        path_id: Unique path identifier
        name: Path name
        description: Path description
        difficulty: Path difficulty level
        tasks: List of task definitions in order
        total_points: Total points available
        estimated_total_hours: Estimated total completion time
    """
    path_id: str = ""
    name: str = ""
    description: str = ""
    difficulty: PathDifficulty = PathDifficulty.BEGINNER
    tasks: List[TaskDefinition] = field(default_factory=list)
    total_points: int = 0
    estimated_total_hours: float = 0.0


@dataclass
class UserProgress:
    """User overall learning progress.

    Attributes:
        user_id: User identifier
        total_points: Total points earned
        tasks_completed: Total tasks completed
        paths_started: List of started path IDs
        paths_completed: List of completed path IDs
        task_progress: Dictionary of task progress
        achievements: List of achievement IDs
        skill_scores: Dictionary of skill area scores
        started_at: Learning start time
        last_active: Last activity timestamp
    """
    user_id: str = ""
    total_points: int = 0
    tasks_completed: int = 0
    paths_started: List[str] = field(default_factory=list)
    paths_completed: List[str] = field(default_factory=list)
    task_progress: Dict[str, TaskProgress] = field(default_factory=dict)
    achievements: List[str] = field(default_factory=list)
    skill_scores: Dict[str, float] = field(default_factory=dict)
    started_at: float = 0.0
    last_active: float = 0.0


class LearningPathManager:
    """Learning path manager with task definitions and unlock logic.

    Manages beginner, intermediate, and advanced learning paths
    with automatic task unlocking upon completion.
    """

    def __init__(self, storage_path: str = "") -> None:
        """Initialize learning path manager.

        Args:
            storage_path: Directory path for user progress storage.
        """
        self.storage_path = storage_path
        self._paths: Dict[str, LearningPath] = {}
        self._user_progress: Dict[str, UserProgress] = {}

        if storage_path:
            os.makedirs(storage_path, exist_ok=True)
            self._load_user_progress()

        self._initialize_paths()

    def _initialize_paths(self) -> None:
        """Initialize built-in learning paths."""
        self._paths["beginner"] = self._create_beginner_path()
        self._paths["intermediate"] = self._create_intermediate_path()
        self._paths["advanced"] = self._create_advanced_path()

    def _create_beginner_path(self) -> LearningPath:
        """Create beginner learning path.

        Returns:
            LearningPath for beginners.
        """
        tasks = [
            TaskDefinition(
                task_id="beginner_01",
                title="Information Gathering - DVWA Recon",
                description="Use Kunlun's proxy and asset discovery modules to gather information about the DVWA target. Identify the technology stack, exposed endpoints, and default login page.",
                category=TaskCategory.INFORMATION_GATHERING,
                difficulty=PathDifficulty.BEGINNER,
                range_id="dvwa",
                prerequisites=[],
                objectives=[
                    "Identify the target technology stack (PHP/MySQL)",
                    "Map all accessible endpoints",
                    "Find the default login page",
                    "Capture login request using proxy",
                ],
                hints=[
                    Hint(level=HintLevel.VAGUE, content="Start by visiting the target URL and observe the response headers.", points_cost=10),
                    Hint(level=HintLevel.SPECIFIC, content="Use Kunlun's proxy to intercept traffic. Look for 'X-Powered-By' and 'Server' headers.", points_cost=20),
                    Hint(level=HintLevel.STEP_BY_STEP, content="1. Open Kunlun proxy. 2. Visit http://target/dvwa. 3. Check response headers. 4. Use asset discovery to map endpoints.", points_cost=40),
                ],
                full_solution="1. Configure Kunlun proxy to intercept DVWA traffic. 2. Visit the target URL. 3. Observe 'X-Powered-By: PHP' header. 4. Use the asset discovery module to enumerate endpoints. 5. Document all findings in the asset library.",
                expected_flags=["php_version_identified", "endpoints_mapped"],
                points_reward=100,
                estimated_time_minutes=30,
                required_modules=["proxy", "asset_discovery"],
                mitre_techniques=["T1595", "T1592"],
                created_at=time.time(),
            ),
            TaskDefinition(
                task_id="beginner_02",
                title="SQL Injection - Low Security Level",
                description="Exploit SQL injection vulnerability in DVWA's login form at low security level. Understand how user input is directly concatenated into SQL queries.",
                category=TaskCategory.EXPLOITATION,
                difficulty=PathDifficulty.BEGINNER,
                range_id="dvwa",
                prerequisites=["beginner_01"],
                objectives=[
                    "Identify the SQL injection point in login form",
                    "Craft a basic SQL injection payload",
                    "Bypass authentication using SQL injection",
                    "Understand the vulnerability principle",
                ],
                hints=[
                    Hint(level=HintLevel.VAGUE, content="Try entering special characters in the login form and observe the response.", points_cost=10),
                    Hint(level=HintLevel.SPECIFIC, content="Try ' OR '1'='1 in the username field. This is a classic SQL injection payload.", points_cost=20),
                    Hint(level=HintLevel.STEP_BY_STEP, content="1. Intercept login request with proxy. 2. Modify username parameter to: admin' OR '1'='1' --. 3. Forward the request. 4. Observe successful login.", points_cost=40),
                ],
                full_solution="1. Use Kunlun's Repeater module to intercept the login request. 2. Modify the username parameter to: admin' OR '1'='1' --. 3. Forward the modified request. 4. The SQL query becomes: SELECT * FROM users WHERE username='admin' OR '1'='1' --' AND password='...'. 5. This always evaluates to true, bypassing authentication.",
                expected_flags=["auth_bypassed"],
                points_reward=150,
                estimated_time_minutes=45,
                required_modules=["proxy", "repeater"],
                mitre_techniques=["T1190", "T1078"],
                created_at=time.time(),
            ),
            TaskDefinition(
                task_id="beginner_03",
                title="XSS - Reflected Cross-Site Scripting",
                description="Exploit reflected XSS vulnerability in DVWA. Understand how user input is reflected in the response without proper sanitization.",
                category=TaskCategory.EXPLOITATION,
                difficulty=PathDifficulty.BEGINNER,
                range_id="dvwa",
                prerequisites=["beginner_02"],
                objectives=[
                    "Identify the XSS injection point",
                    "Craft a basic XSS payload",
                    "Execute JavaScript in the target context",
                    "Understand XSS impact and risks",
                ],
                hints=[
                    Hint(level=HintLevel.VAGUE, content="Try entering HTML tags in the input field and see if they render.", points_cost=10),
                    Hint(level=HintLevel.SPECIFIC, content="Try <script>alert('XSS')</script> in the search/input field.", points_cost=20),
                    Hint(level=HintLevel.STEP_BY_STEP, content="1. Navigate to the XSS reflected page. 2. Enter <script>alert(document.cookie)</script>. 3. Submit and observe the alert. 4. Use Kunlun's Fuzzer to automate payload testing.", points_cost=40),
                ],
                full_solution="1. Navigate to DVWA XSS (Reflected) page. 2. Enter payload: <script>alert(document.cookie)</script>. 3. Submit the form. 4. Observe the JavaScript execution. 5. Use Kunlun's Fuzzer module to test multiple XSS payloads automatically. 6. Document the vulnerable parameter and payload.",
                expected_flags=["xss_executed"],
                points_reward=150,
                estimated_time_minutes=45,
                required_modules=["proxy", "fuzzer"],
                mitre_techniques=["T1059"],
                created_at=time.time(),
            ),
            TaskDefinition(
                task_id="beginner_04",
                title="File Upload - Basic Upload Bypass",
                description="Exploit file upload vulnerability in DVWA. Upload a PHP web shell and understand the risks of unrestricted file uploads.",
                category=TaskCategory.EXPLOITATION,
                difficulty=PathDifficulty.BEGINNER,
                range_id="dvwa",
                prerequisites=["beginner_03"],
                objectives=[
                    "Identify the file upload functionality",
                    "Upload a PHP web shell",
                    "Access the uploaded shell",
                    "Execute system commands through the shell",
                ],
                hints=[
                    Hint(level=HintLevel.VAGUE, content="Try uploading a simple PHP file and see if it executes.", points_cost=10),
                    Hint(level=HintLevel.SPECIFIC, content="Create a file named shell.php with content: <?php system($_GET['cmd']); ?>", points_cost=20),
                    Hint(level=HintLevel.STEP_BY_STEP, content="1. Create shell.php with system() function. 2. Upload through DVWA file upload page. 3. Access the uploaded file via URL. 4. Add ?cmd=id parameter to execute commands.", points_cost=40),
                ],
                full_solution="1. Create a PHP web shell: <?php system($_GET['cmd']); ?>. 2. Upload through DVWA's file upload page at low security. 3. Note the upload path from the response. 4. Access the shell via browser: http://target/hackable/uploads/shell.php?cmd=id. 5. Use Kunlun's Web Shell module for interactive command execution.",
                expected_flags=["shell_uploaded", "command_executed"],
                points_reward=200,
                estimated_time_minutes=60,
                required_modules=["proxy", "web_shell"],
                mitre_techniques=["T1505", "T1059"],
                created_at=time.time(),
            ),
            TaskDefinition(
                task_id="beginner_05",
                title="CSRF - Cross-Site Request Forgery",
                description="Exploit CSRF vulnerability in DVWA's password change functionality. Understand how missing anti-CSRF tokens enable request forgery.",
                category=TaskCategory.EXPLOITATION,
                difficulty=PathDifficulty.BEGINNER,
                range_id="dvwa",
                prerequisites=["beginner_04"],
                objectives=[
                    "Identify the CSRF vulnerability in password change",
                    "Craft a CSRF exploit page",
                    "Change another user's password via CSRF",
                    "Understand CSRF prevention mechanisms",
                ],
                hints=[
                    Hint(level=HintLevel.VAGUE, content="Check if the password change request requires any special tokens.", points_cost=10),
                    Hint(level=HintLevel.SPECIFIC, content="Create an HTML page that automatically submits a password change request to the target.", points_cost=20),
                    Hint(level=HintLevel.STEP_BY_STEP, content="1. Intercept password change request. 2. Note there's no CSRF token. 3. Create HTML form with action pointing to password change URL. 4. Auto-submit the form when victim visits.", points_cost=40),
                ],
                full_solution="1. Intercept password change request with Kunlun proxy. 2. Observe no CSRF token in the request. 3. Create HTML form: <form action='http://target/dvwa/vulnerabilities/csrf/' method='GET'><input name='password_new' value='hacked'><input name='password_conf' value='hacked'><input type='submit'></form>. 4. When authenticated user visits this page, their password changes.",
                expected_flags=["csrf_exploited"],
                points_reward=200,
                estimated_time_minutes=60,
                required_modules=["proxy", "repeater"],
                mitre_techniques=["T1078"],
                created_at=time.time(),
            ),
        ]

        total_points = sum(t.points_reward for t in tasks)
        total_hours = sum(t.estimated_time_minutes for t in tasks) / 60.0

        return LearningPath(
            path_id="beginner",
            name="Beginner Path - Web Vulnerability Fundamentals",
            description="Learn the fundamentals of web vulnerability discovery and exploitation through hands-on exercises with DVWA.",
            difficulty=PathDifficulty.BEGINNER,
            tasks=tasks,
            total_points=total_points,
            estimated_total_hours=total_hours,
        )

    def _create_intermediate_path(self) -> LearningPath:
        """Create intermediate learning path.

        Returns:
            LearningPath for intermediate level.
        """
        tasks = [
            TaskDefinition(
                task_id="intermediate_01",
                title="Blind SQL Injection - Time-Based",
                description="Exploit time-based blind SQL injection in DVWA. Extract database information without visible error messages or output.",
                category=TaskCategory.EXPLOITATION,
                difficulty=PathDifficulty.INTERMEDIATE,
                range_id="dvwa",
                prerequisites=[],
                objectives=[
                    "Identify blind SQL injection point",
                    "Use time-based techniques to confirm injection",
                    "Extract database name character by character",
                    "Automate extraction using Kunlun's tools",
                ],
                hints=[
                    Hint(level=HintLevel.VAGUE, content="Try adding sleep functions to the input and observe response time.", points_cost=15),
                    Hint(level=HintLevel.SPECIFIC, content="Use: ' AND SLEEP(5) -- to test for time-based injection.", points_cost=30),
                    Hint(level=HintLevel.STEP_BY_STEP, content="1. Intercept the request. 2. Add payload: 1' AND IF(SUBSTRING(database(),1,1)='d',SLEEP(3),0) --. 3. Measure response time. 4. Use Kunlun's SQLi module to automate extraction.", points_cost=50),
                ],
                full_solution="1. Use Kunlun's SQL injection module with blind mode enabled. 2. Configure time-based detection with 3-second threshold. 3. The module will automatically extract database name, table names, and column data by measuring response delays. 4. Review extracted data in the module results panel.",
                expected_flags=["database_name_extracted", "table_names_extracted"],
                points_reward=250,
                estimated_time_minutes=90,
                required_modules=["proxy", "sqli_module"],
                mitre_techniques=["T1190"],
                created_at=time.time(),
            ),
            TaskDefinition(
                task_id="intermediate_02",
                title="JWT Token Manipulation",
                description="Exploit JWT authentication weaknesses in OWASP Juice Shop. Understand common JWT vulnerabilities and bypass techniques.",
                category=TaskCategory.EXPLOITATION,
                difficulty=PathDifficulty.INTERMEDIATE,
                range_id="juice_shop",
                prerequisites=["intermediate_01"],
                objectives=[
                    "Identify JWT authentication mechanism",
                    "Decode and analyze JWT token structure",
                    "Exploit 'none' algorithm vulnerability",
                    "Forge admin JWT token",
                ],
                hints=[
                    Hint(level=HintLevel.VAGUE, content="Capture the authentication token and analyze its structure.", points_cost=15),
                    Hint(level=HintLevel.SPECIFIC, content="Try changing the algorithm to 'none' and removing the signature.", points_cost=30),
                    Hint(level=HintLevel.STEP_BY_STEP, content="1. Intercept login request. 2. Decode JWT at jwt.io. 3. Change 'alg' to 'none'. 4. Change 'role' to 'admin'. 5. Remove signature. 6. Use modified token.", points_cost=50),
                ],
                full_solution="1. Use Kunlun's JWT module to capture and decode tokens. 2. Analyze the token structure: header, payload, signature. 3. Change algorithm to 'none' and modify role claim to 'admin'. 4. Remove the signature part. 5. Use the forged token to access admin endpoints. 6. Document the vulnerability and impact.",
                expected_flags=["admin_access_gained"],
                points_reward=300,
                estimated_time_minutes=90,
                required_modules=["proxy", "jwt_module"],
                mitre_techniques=["T1078", "T1550"],
                created_at=time.time(),
            ),
            TaskDefinition(
                task_id="intermediate_03",
                title="IDOR - Insecure Direct Object Reference",
                description="Exploit IDOR vulnerability in Hackazon's API. Access other users' data by manipulating object identifiers in API requests.",
                category=TaskCategory.EXPLOITATION,
                difficulty=PathDifficulty.INTERMEDIATE,
                range_id="hackazon",
                prerequisites=["intermediate_02"],
                objectives=[
                    "Identify API endpoints with object references",
                    "Manipulate user/order IDs in requests",
                    "Access other users' data",
                    "Understand authorization vs authentication",
                ],
                hints=[
                    Hint(level=HintLevel.VAGUE, content="Look for numeric IDs in API requests and try changing them.", points_cost=15),
                    Hint(level=HintLevel.SPECIFIC, content="Try changing the user_id or order_id parameter to access other users' data.", points_cost=30),
                    Hint(level=HintLevel.STEP_BY_STEP, content="1. Intercept API requests with Kunlun proxy. 2. Note numeric IDs in URLs or parameters. 3. Use Repeater to modify IDs. 4. Check if you can access other users' orders/profiles.", points_cost=50),
                ],
                full_solution="1. Use Kunlun proxy to intercept API requests. 2. Identify endpoints like /api/orders/{id} or /api/users/{id}. 3. Use Repeater to change the ID to another user's ID. 4. If the server returns the data without proper authorization check, IDOR exists. 5. Use Kunlun's IDOR module to automate testing across all endpoints.",
                expected_flags=["idor_confirmed", "other_user_data_accessed"],
                points_reward=250,
                estimated_time_minutes=75,
                required_modules=["proxy", "repeater", "idor_module"],
                mitre_techniques=["T1078"],
                created_at=time.time(),
            ),
            TaskDefinition(
                task_id="intermediate_04",
                title="SSRF - Server-Side Request Forgery",
                description="Exploit SSRF vulnerability to access internal services. Understand how server-side requests can be manipulated to reach internal resources.",
                category=TaskCategory.EXPLOITATION,
                difficulty=PathDifficulty.INTERMEDIATE,
                range_id="webgoat",
                prerequisites=["intermediate_03"],
                objectives=[
                    "Identify SSRF injection point",
                    "Access internal metadata service",
                    "Scan internal network through SSRF",
                    "Understand SSRF impact and mitigation",
                ],
                hints=[
                    Hint(level=HintLevel.VAGUE, content="Try providing internal URLs in features that fetch external resources.", points_cost=15),
                    Hint(level=HintLevel.SPECIFIC, content="Try http://localhost:8080 or http://169.254.169.254 (cloud metadata).", points_cost=30),
                    Hint(level=HintLevel.STEP_BY_STEP, content="1. Find feature that fetches URLs (image preview, webhook, etc.). 2. Intercept the request. 3. Change URL to http://localhost:8080/admin. 4. Observe internal service response.", points_cost=50),
                ],
                full_solution="1. Identify feature that fetches external URLs. 2. Use Kunlun's SSRF module to test various internal targets. 3. Try cloud metadata endpoints: http://169.254.169.254/latest/meta-data/. 4. Scan internal services: http://localhost:8080, http://127.0.0.1:6379. 5. Document all accessible internal services.",
                expected_flags=["internal_service_accessed", "metadata_retrieved"],
                points_reward=300,
                estimated_time_minutes=90,
                required_modules=["proxy", "ssrf_module"],
                mitre_techniques=["T1190"],
                created_at=time.time(),
            ),
        ]

        total_points = sum(t.points_reward for t in tasks)
        total_hours = sum(t.estimated_time_minutes for t in tasks) / 60.0

        return LearningPath(
            path_id="intermediate",
            name="Intermediate Path - Advanced Web Exploitation",
            description="Master advanced web exploitation techniques including blind SQL injection, JWT manipulation, IDOR, and SSRF.",
            difficulty=PathDifficulty.INTERMEDIATE,
            tasks=tasks,
            total_points=total_points,
            estimated_total_hours=total_hours,
        )

    def _create_advanced_path(self) -> LearningPath:
        """Create advanced learning path.

        Returns:
            LearningPath for advanced level.
        """
        tasks = [
            TaskDefinition(
                task_id="advanced_01",
                title="Deserialization Attack - Java",
                description="Exploit Java deserialization vulnerability in WebGoat. Craft malicious serialized objects to achieve remote code execution.",
                category=TaskCategory.EXPLOITATION,
                difficulty=PathDifficulty.ADVANCED,
                range_id="webgoat",
                prerequisites=[],
                objectives=[
                    "Identify deserialization endpoint",
                    "Understand Java serialization format",
                    "Craft malicious serialized payload",
                    "Achieve remote code execution",
                ],
                hints=[
                    Hint(level=HintLevel.VAGUE, content="Look for base64-encoded data in requests that might be serialized Java objects.", points_cost=20),
                    Hint(level=HintLevel.SPECIFIC, content="Use ysoserial to generate payloads for common Java libraries (CommonsCollections, CommonsBeanutils).", points_cost=40),
                    Hint(level=HintLevel.STEP_BY_STEP, content="1. Identify endpoint accepting serialized data. 2. Use ysoserial to generate payload: java -jar ysoserial.jar CommonsCollections5 'cmd'. 3. Base64 encode the payload. 4. Send via Kunlun Repeater.", points_cost=60),
                ],
                full_solution="1. Identify endpoint accepting Java serialized objects (look for 'rO0AB' prefix in base64 data). 2. Use ysoserial to generate payload for the target library. 3. Base64 encode the malicious object. 4. Use Kunlun's Repeater to send the payload. 5. Observe command execution in the response or out-of-band callback.",
                expected_flags=["rce_achieved"],
                points_reward=400,
                estimated_time_minutes=120,
                required_modules=["proxy", "repeater", "deserialization_module"],
                mitre_techniques=["T1190", "T1059"],
                created_at=time.time(),
            ),
            TaskDefinition(
                task_id="advanced_02",
                title="WAF Bypass Techniques",
                description="Bypass Web Application Firewall protections in PortSwigger labs. Learn various WAF bypass techniques for common vulnerability types.",
                category=TaskCategory.EXPLOITATION,
                difficulty=PathDifficulty.ADVANCED,
                range_id="portswigger_web_security",
                prerequisites=["advanced_01"],
                objectives=[
                    "Identify WAF protection mechanisms",
                    "Analyze WAF blocking patterns",
                    "Apply encoding bypass techniques",
                    "Develop custom bypass payloads",
                ],
                hints=[
                    Hint(level=HintLevel.VAGUE, content="Try different encoding methods for your payloads.", points_cost=20),
                    Hint(level=HintLevel.SPECIFIC, content="Use URL encoding, double encoding, or case variation to bypass pattern matching.", points_cost=40),
                    Hint(level=HintLevel.STEP_BY_STEP, content="1. Send basic payload and observe WAF block. 2. Try URL encoding: %3Cscript%3E. 3. Try double encoding: %253Cscript%253E. 4. Try case variation: <ScRiPt>. 5. Use Kunlun's WAF bypass module for automated testing.", points_cost=60),
                ],
                full_solution="1. Send baseline payload to identify WAF rules. 2. Use Kunlun's WAF bypass module to test multiple encoding techniques. 3. Try: URL encoding, HTML entity encoding, Unicode encoding, case variation, comment insertion. 4. Combine techniques for complex WAF rules. 5. Document successful bypass patterns.",
                expected_flags=["waf_bypassed", "payload_executed"],
                points_reward=400,
                estimated_time_minutes=120,
                required_modules=["proxy", "fuzzer", "waf_bypass_module"],
                mitre_techniques=["T1190"],
                created_at=time.time(),
            ),
            TaskDefinition(
                task_id="advanced_03",
                title="Multi-Stage Attack Chain",
                description="Build a complete attack chain combining multiple vulnerabilities. Practice chaining exploits for maximum impact.",
                category=TaskCategory.POST_EXPLOITATION,
                difficulty=PathDifficulty.ADVANCED,
                range_id="portswigger_web_security",
                prerequisites=["advanced_02"],
                objectives=[
                    "Identify multiple vulnerabilities in target",
                    "Chain vulnerabilities for escalation",
                    "Achieve full system compromise",
                    "Document complete attack chain",
                ],
                hints=[
                    Hint(level=HintLevel.VAGUE, content="Look for ways to combine the vulnerabilities you've found.", points_cost=20),
                    Hint(level=HintLevel.SPECIFIC, content="Can you use XSS to steal CSRF tokens? Can you use SQL injection to get credentials for file upload?", points_cost=40),
                    Hint(level=HintLevel.STEP_BY_STEP, content="1. Map all vulnerabilities. 2. Identify escalation paths. 3. Build chain: Info gathering -> Initial access -> Privilege escalation -> Persistence. 4. Use Kunlun's attack chain module to document.", points_cost=60),
                ],
                full_solution="1. Complete full reconnaissance of target. 2. Identify all vulnerabilities. 3. Build attack chain: e.g., SSRF -> Internal service access -> Credential theft -> Admin panel access -> File upload -> RCE. 4. Execute each step methodically. 5. Use Kunlun's attack chain module to document and visualize the complete chain.",
                expected_flags=["full_compromise", "attack_chain_documented"],
                points_reward=500,
                estimated_time_minutes=180,
                required_modules=["proxy", "repeater", "fuzzer", "attack_chain_module"],
                mitre_techniques=["T1190", "T1078", "T1059", "T1505"],
                created_at=time.time(),
            ),
        ]

        total_points = sum(t.points_reward for t in tasks)
        total_hours = sum(t.estimated_time_minutes for t in tasks) / 60.0

        return LearningPath(
            path_id="advanced",
            name="Advanced Path - Complex Attack Chains",
            description="Master complex attack chains, WAF bypass techniques, and multi-stage exploitation for real-world scenarios.",
            difficulty=PathDifficulty.ADVANCED,
            tasks=tasks,
            total_points=total_points,
            estimated_total_hours=total_hours,
        )

    def get_path(self, path_id: str) -> Optional[LearningPath]:
        """Get learning path by ID.

        Args:
            path_id: Path identifier.

        Returns:
            LearningPath or None if not found.
        """
        return self._paths.get(path_id)

    def get_all_paths(self) -> List[LearningPath]:
        """Get all learning paths.

        Returns:
            List of all LearningPath objects.
        """
        return list(self._paths.values())

    def get_user_progress(self, user_id: str) -> UserProgress:
        """Get or create user progress.

        Args:
            user_id: User identifier.

        Returns:
            UserProgress object.
        """
        if user_id not in self._user_progress:
            self._user_progress[user_id] = UserProgress(
                user_id=user_id,
                started_at=time.time(),
                last_active=time.time(),
            )

        return self._user_progress[user_id]

    def start_task(self, user_id: str, task_id: str) -> bool:
        """Start a task for user.

        Args:
            user_id: User identifier.
            task_id: Task identifier.

        Returns:
            True if task started successfully.
        """
        user_progress = self.get_user_progress(user_id)

        if task_id in user_progress.task_progress:
            existing = user_progress.task_progress[task_id]
            if existing.status == TaskStatus.COMPLETED:
                return False

        user_progress.task_progress[task_id] = TaskProgress(
            task_id=task_id,
            status=TaskStatus.IN_PROGRESS,
            started_at=time.time(),
        )
        user_progress.last_active = time.time()

        self._save_user_progress()
        return True

    def complete_task(
        self,
        user_id: str,
        task_id: str,
        flags_found: Optional[List[str]] = None,
        modules_used: Optional[List[str]] = None,
    ) -> bool:
        """Complete a task for user.

        Args:
            user_id: User identifier.
            task_id: Task identifier.
            flags_found: List of flags found during task.
            modules_used: List of modules used during task.

        Returns:
            True if task completed successfully.
        """
        user_progress = self.get_user_progress(user_id)

        task_progress = user_progress.task_progress.get(task_id)
        if not task_progress:
            return False

        task_progress.status = TaskStatus.COMPLETED
        task_progress.completed_at = time.time()
        task_progress.time_spent_seconds = task_progress.completed_at - task_progress.started_at

        if flags_found:
            task_progress.flags_found = flags_found
        if modules_used:
            task_progress.modules_used = modules_used

        task_points = self._get_task_points(task_id)
        user_progress.total_points += task_points
        user_progress.tasks_completed += 1
        user_progress.last_active = time.time()

        self._update_skill_scores(user_id, task_id)
        self._check_achievements(user_id)
        self._unlock_next_tasks(user_id, task_id)

        self._save_user_progress()
        return True

    def get_available_tasks(self, user_id: str) -> List[TaskDefinition]:
        """Get tasks available for user to attempt.

        Args:
            user_id: User identifier.

        Returns:
            List of available TaskDefinition objects.
        """
        user_progress = self.get_user_progress(user_id)
        available: List[TaskDefinition] = []

        for path in self._paths.values():
            for task in path.tasks:
                if task.task_id in user_progress.task_progress:
                    existing = user_progress.task_progress[task.task_id]
                    if existing.status == TaskStatus.COMPLETED:
                        continue

                if self._is_task_unlocked(task, user_progress):
                    available.append(task)

        return available

    def get_hint(self, user_id: str, task_id: str, hint_level: HintLevel) -> Optional[Hint]:
        """Get hint for task.

        Args:
            user_id: User identifier.
            task_id: Task identifier.
            hint_level: Desired hint level.

        Returns:
            Hint or None if not available.
        """
        task = self._find_task(task_id)
        if not task:
            return None

        user_progress = self.get_user_progress(user_id)
        task_progress = user_progress.task_progress.get(task_id)

        if not task_progress:
            return None

        for hint in task.hints:
            if hint.level == hint_level:
                user_progress.total_points -= hint.points_cost
                task_progress.points_spent += hint.points_cost
                task_progress.hints_used.append(hint_level)

                self._save_user_progress()
                return hint

        return None

    def get_full_solution(self, user_id: str, task_id: str) -> Optional[str]:
        """Get full solution for task.

        Args:
            user_id: User identifier.
            task_id: Task identifier.

        Returns:
            Full solution text or None.
        """
        task = self._find_task(task_id)
        if not task:
            return None

        return task.full_solution

    def _is_task_unlocked(self, task: TaskDefinition, user_progress: UserProgress) -> bool:
        """Check if task is unlocked for user.

        Args:
            task: Task definition.
            user_progress: User progress.

        Returns:
            True if task is unlocked.
        """
        if not task.prerequisites:
            return True

        for prereq_id in task.prerequisites:
            prereq_progress = user_progress.task_progress.get(prereq_id)
            if not prereq_progress or prereq_progress.status != TaskStatus.COMPLETED:
                return False

        return True

    def _unlock_next_tasks(self, user_id: str, completed_task_id: str) -> None:
        """Unlock next tasks after completing a task.

        Args:
            user_id: User identifier.
            completed_task_id: Completed task ID.
        """
        pass

    def _get_task_points(self, task_id: str) -> int:
        """Get points reward for task.

        Args:
            task_id: Task identifier.

        Returns:
            Points reward.
        """
        for path in self._paths.values():
            for task in path.tasks:
                if task.task_id == task_id:
                    return task.points_reward
        return 0

    def _find_task(self, task_id: str) -> Optional[TaskDefinition]:
        """Find task definition by ID.

        Args:
            task_id: Task identifier.

        Returns:
            TaskDefinition or None.
        """
        for path in self._paths.values():
            for task in path.tasks:
                if task.task_id == task_id:
                    return task
        return None

    def _update_skill_scores(self, user_id: str, task_id: str) -> None:
        """Update user skill scores after task completion.

        Args:
            user_id: User identifier.
            task_id: Completed task ID.
        """
        user_progress = self.get_user_progress(user_id)
        task = self._find_task(task_id)

        if not task:
            return

        category = task.category.value
        current_score = user_progress.skill_scores.get(category, 0.0)
        user_progress.skill_scores[category] = current_score + task.points_reward

    def _check_achievements(self, user_id: str) -> None:
        """Check and award achievements.

        Args:
            user_id: User identifier.
        """
        user_progress = self.get_user_progress(user_id)

        if user_progress.tasks_completed >= 1 and "first_task" not in user_progress.achievements:
            user_progress.achievements.append("first_task")

        if user_progress.tasks_completed >= 5 and "five_tasks" not in user_progress.achievements:
            user_progress.achievements.append("five_tasks")

        if user_progress.tasks_completed >= 10 and "ten_tasks" not in user_progress.achievements:
            user_progress.achievements.append("ten_tasks")

        if user_progress.total_points >= 500 and "points_500" not in user_progress.achievements:
            user_progress.achievements.append("points_500")

        if user_progress.total_points >= 1000 and "points_1000" not in user_progress.achievements:
            user_progress.achievements.append("points_1000")

    def _load_user_progress(self) -> None:
        """Load user progress from storage."""
        if not self.storage_path:
            return

        try:
            progress_file = os.path.join(self.storage_path, "user_progress.json")
            if os.path.exists(progress_file):
                with open(progress_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for user_id, user_data in data.items():
                        user_progress = UserProgress(
                            user_id=user_data.get("user_id", user_id),
                            total_points=user_data.get("total_points", 0),
                            tasks_completed=user_data.get("tasks_completed", 0),
                            paths_started=user_data.get("paths_started", []),
                            paths_completed=user_data.get("paths_completed", []),
                            achievements=user_data.get("achievements", []),
                            skill_scores=user_data.get("skill_scores", {}),
                            started_at=user_data.get("started_at", time.time()),
                            last_active=user_data.get("last_active", time.time()),
                        )

                        task_progress_data = user_data.get("task_progress", {})
                        for task_id, tp_data in task_progress_data.items():
                            user_progress.task_progress[task_id] = TaskProgress(
                                task_id=tp_data.get("task_id", task_id),
                                status=TaskStatus(tp_data.get("status", "locked")),
                                started_at=tp_data.get("started_at", 0.0),
                                completed_at=tp_data.get("completed_at", 0.0),
                                attempts=tp_data.get("attempts", 0),
                                hints_used=[HintLevel(h) for h in tp_data.get("hints_used", [])],
                                points_spent=tp_data.get("points_spent", 0),
                                flags_found=tp_data.get("flags_found", []),
                                modules_used=tp_data.get("modules_used", []),
                                time_spent_seconds=tp_data.get("time_spent_seconds", 0.0),
                                notes=tp_data.get("notes", ""),
                            )

                        self._user_progress[user_id] = user_progress

        except Exception as e:
            logger.error(f"Failed to load user progress: {e}")

    def _save_user_progress(self) -> None:
        """Save user progress to storage."""
        if not self.storage_path:
            return

        try:
            progress_file = os.path.join(self.storage_path, "user_progress.json")
            data = {}

            for user_id, user_progress in self._user_progress.items():
                task_progress_dict = {}
                for task_id, tp in user_progress.task_progress.items():
                    task_progress_dict[task_id] = {
                        "task_id": tp.task_id,
                        "status": tp.status.value,
                        "started_at": tp.started_at,
                        "completed_at": tp.completed_at,
                        "attempts": tp.attempts,
                        "hints_used": [h.value for h in tp.hints_used],
                        "points_spent": tp.points_spent,
                        "flags_found": tp.flags_found,
                        "modules_used": tp.modules_used,
                        "time_spent_seconds": tp.time_spent_seconds,
                        "notes": tp.notes,
                    }

                data[user_id] = {
                    "user_id": user_progress.user_id,
                    "total_points": user_progress.total_points,
                    "tasks_completed": user_progress.tasks_completed,
                    "paths_started": user_progress.paths_started,
                    "paths_completed": user_progress.paths_completed,
                    "task_progress": task_progress_dict,
                    "achievements": user_progress.achievements,
                    "skill_scores": user_progress.skill_scores,
                    "started_at": user_progress.started_at,
                    "last_active": user_progress.last_active,
                }

            with open(progress_file, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)

        except Exception as e:
            logger.error(f"Failed to save user progress: {e}")
