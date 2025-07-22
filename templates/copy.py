from flask import Flask, request, render_template, redirect, url_for, jsonify, send_file
import os
import re
import hashlib
import secrets
import tempfile
from datetime import datetime
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
import json
from io import BytesIO
import zipfile
import mimetypes
from pathlib import Path

app = Flask(__name__)

# Security Configuration
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # Increased to 50MB max file size
app.config['UPLOAD_FOLDER'] = tempfile.mkdtemp()  # Use temporary directory

# Expanded allowed file extensions - more permissive
ALLOWED_EXTENSIONS = {
    'php', 'js', 'html', 'htm', 'py', 'jsx', 'ts', 'tsx', 'css', 'json', 'xml',
    'txt', 'java', 'c', 'cpp', 'cc', 'cxx', 'h', 'hpp', 'cs', 'vb', 'rb', 'go',
    'rs', 'swift', 'kt', 'scala', 'pl', 'r', 'sql', 'sh', 'bash', 'ps1', 'bat',
    'yaml', 'yml', 'ini', 'cfg', 'conf', 'properties', 'asp', 'aspx', 'jsp',
    'vue', 'svelte', 'dart', 'lua', 'perl', 'asm', 's', 'f', 'f90', 'f95',
    'pas', 'pp', 'inc', 'ino', 'pde', 'm', 'mm', 'swift', 'groovy', 'clj',
    'cljs', 'ex', 'exs', 'elm', 'hs', 'lhs', 'ml', 'mli', 'fs', 'fsx', 'fsi'
}

# Security headers middleware
@app.after_request
def after_request(response):
    """Add security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; script-src 'self' 'unsafe-inline'; font-src 'self' https://cdnjs.cloudflare.com"
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

def is_safe_file(filename, file_content):
    """Relaxed file safety checks - more permissive"""
    # Check file size (only major restriction kept)
    if len(file_content) > app.config['MAX_CONTENT_LENGTH']:
        return False, "File too large"
    
    # Very basic filename validation - only block obviously malicious patterns
    dangerous_patterns = [
        r'\.\..*\.\.', r'<script.*>.*</script>', r'\.exe$', r'\.bat$', r'\.cmd$'
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, filename, re.IGNORECASE):
            return False, "Potentially dangerous file type detected"
    
    return True, "File is safe"

def allowed_file(filename):
    """More permissive file extension check"""
    if '.' not in filename:
        return True  # Allow files without extensions
    
    extension = filename.rsplit('.', 1)[1].lower()
    # Allow if extension is in our list OR if it's a common text-based extension
    return extension in ALLOWED_EXTENSIONS or len(extension) <= 10

def get_file_hash(filepath):
    """Generate SHA-256 hash of file for security tracking"""
    hash_sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    except Exception:
        return None

def detect_language(filename):
    """Detect programming language from file extension"""
    if '.' not in filename:
        return 'Unknown'
    
    ext = filename.rsplit('.', 1)[1].lower()
    language_map = {
        'php': 'PHP',
        'js': 'JavaScript',
        'jsx': 'JavaScript (React)',
        'ts': 'TypeScript',
        'tsx': 'TypeScript (React)',
        'html': 'HTML',
        'htm': 'HTML',
        'py': 'Python',
        'css': 'CSS',
        'json': 'JSON',
        'xml': 'XML',
        'java': 'Java',
        'c': 'C',
        'cpp': 'C++',
        'cc': 'C++',
        'cxx': 'C++',
        'h': 'C/C++ Header',
        'hpp': 'C++ Header',
        'cs': 'C#',
        'vb': 'Visual Basic',
        'rb': 'Ruby',
        'go': 'Go',
        'rs': 'Rust',
        'swift': 'Swift',
        'kt': 'Kotlin',
        'scala': 'Scala',
        'pl': 'Perl',
        'r': 'R',
        'sql': 'SQL',
        'sh': 'Shell Script',
        'bash': 'Bash Script',
        'ps1': 'PowerShell',
        'bat': 'Batch File',
        'yaml': 'YAML',
        'yml': 'YAML',
        'asp': 'ASP',
        'aspx': 'ASP.NET',
        'jsp': 'JSP',
        'vue': 'Vue.js',
        'dart': 'Dart',
        'lua': 'Lua',
        'txt': 'Text File'
    }
    return language_map.get(ext, 'Unknown')

def get_vulnerability_patterns():
    """Return comprehensive vulnerability patterns for different languages"""
    return {
        'PHP': {
            "SQL Injection": [
                r"\b(mysql_query|mysqli_query|pg_query|PDO::query)\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)\[[^\]]*\][^)]*\)",
                r"(SELECT|INSERT|UPDATE|DELETE)\s+[^;]*\$_(GET|POST|REQUEST|COOKIE)\[[^\]]*\]",
                r"\bquery\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)\[[^\]]*\][^)]*\)",
                r"\bexecute\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)\[[^\]]*\][^)]*\)"
            ],
            "XSS (Cross-Site Scripting)": [
                r"echo\s+\$_(GET|POST|REQUEST|COOKIE)\[[^\]]*\]",
                r"print\s+\$_(GET|POST|REQUEST|COOKIE)\[[^\]]*\]",
                r"<\?php\s*=\s*\$_(GET|POST|REQUEST|COOKIE)\[[^\]]*\]",
                r"printf?\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)\[[^\]]*\][^)]*\)"
            ],
            "Command Injection": [
                r"(exec|shell_exec|system|passthru|popen)\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)\[[^\]]*\][^)]*\)",
                r"backticks.*\$_(GET|POST|REQUEST|COOKIE)\[[^\]]*\]",
                r"proc_open\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)\[[^\]]*\][^)]*\)"
            ],
            "File Inclusion": [
                r"(include|require|include_once|require_once)\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)\[[^\]]*\][^)]*\)",
                r"(include|require|include_once|require_once)\s+\$_(GET|POST|REQUEST|COOKIE)\[[^\]]*\]"
            ],
            "File Upload Vulnerabilities": [
                r"move_uploaded_file\s*\(",
                r"\$_FILES\[[^\]]*\]\[(['\"])name\1\]",
                r"\$_FILES\[[^\]]*\]\[(['\"])tmp_name\1\]",
                r"copy\s*\([^)]*\$_FILES"
            ],
            "Code Injection": [
                r"eval\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)",
                r"assert\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)",
                r"create_function\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)",
                r"preg_replace\s*\([^)]*['\"][^'\"]*e[^'\"]*['\"][^)]*\$_(GET|POST|REQUEST|COOKIE)"
            ],
            "Weak Cryptography": [
                r"\bmd5\s*\(",
                r"\bsha1\s*\(",
                r"\bcrypt\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)",
                r"mcrypt_"
            ],
            "Session Security Issues": [
                r"\$_SESSION\[[^\]]*\]\s*=\s*\$_(GET|POST|REQUEST|COOKIE)\[[^\]]*\]",
                r"session_id\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)"
            ],
            "Information Disclosure": [
                r"\bphpinfo\s*\(\)",
                r"\bvar_dump\s*\(",
                r"\bprint_r\s*\(",
                r"\berror_reporting\s*\(\s*E_ALL",
                r"display_errors\s*=\s*['\"]?on['\"]?"
            ],
            "Hardcoded Credentials": [
                r"(password|passwd|pwd|secret|api_key|apikey|token|key)\s*=\s*['\"][^'\"]{3,}['\"]",
                r"\$\w*(password|passwd|pwd|secret|api_key|apikey|token|key)\w*\s*=\s*['\"][^'\"]{3,}['\"]"
            ],
            "LDAP Injection": [
                r"ldap_search\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)",
                r"ldap_bind\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)"
            ],
            "XML Injection": [
                r"simplexml_load_string\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)",
                r"DOMDocument.*loadXML\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)"
            ]
        },
        'JavaScript': {
            "XSS (Cross-Site Scripting)": [
                r"\.innerHTML\s*=.*[^+]*\+",
                r"\.outerHTML\s*=.*[^+]*\+",
                r"document\.write\s*\(",
                r"document\.writeln\s*\(",
                r"\.insertAdjacentHTML\s*\("
            ],
            "Code Injection": [
                r"\beval\s*\(",
                r"Function\s*\(",
                r"setTimeout\s*\([^)]*['\"][^'\"]*['\"]",
                r"setInterval\s*\([^)]*['\"][^'\"]*['\"]"
            ],
            "DOM Manipulation Vulnerabilities": [
                r"document\.getElementById\([^)]*\)\.innerHTML",
                r"document\.querySelector\([^)]*\)\.innerHTML",
                r"\$\([^)]*\)\.html\s*\("
            ],
            "Unsafe Redirects": [
                r"window\.location\s*=.*[^+]*\+",
                r"location\.href\s*=.*[^+]*\+",
                r"location\.replace\s*\(.*[^+]*\+"
            ],
            "Insecure AJAX": [
                r"XMLHttpRequest\s*\(\)",
                r"\$\.ajax\s*\(",
                r"fetch\s*\(",
                r"\$\.get\s*\(",
                r"\$\.post\s*\("
            ],
            "Local Storage Security": [
                r"localStorage\.setItem",
                r"sessionStorage\.setItem",
                r"localStorage\[.*\]\s*=",
                r"sessionStorage\[.*\]\s*="
            ],
            "Hardcoded Secrets": [
                r"(api_key|apikey|secret|token|password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{5,}['\"]",
                r"(API_KEY|APIKEY|SECRET|TOKEN|PASSWORD)\s*[:=]\s*['\"][^'\"]{5,}['\"]"
            ],
            "Prototype Pollution": [
                r"__proto__",
                r"constructor\.prototype",
                r"\.prototype\[.*\]\s*="
            ],
            "Regular Expression DoS": [
                r"new RegExp\s*\([^)]*\+",
                r"\.match\s*\([^)]*\+",
                r"\.replace\s*\([^)]*\+"
            ]
        },
        'Python': {
            "SQL Injection": [
                r"cursor\.execute\s*\([^)]*%[^)]*\)",
                r"\.execute\s*\([^)]*\+[^)]*\)",
                r"(SELECT|INSERT|UPDATE|DELETE).*\+.*",
                r"(SELECT|INSERT|UPDATE|DELETE).*%.*"
            ],
            "Command Injection": [
                r"os\.system\s*\(",
                r"subprocess\.(call|run|Popen)\s*\(",
                r"os\.popen\s*\(",
                r"commands\.getoutput\s*\("
            ],
            "Code Injection": [
                r"\beval\s*\(",
                r"\bexec\s*\(",
                r"\bcompile\s*\(",
                r"__import__\s*\("
            ],
            "File Path Traversal": [
                r"open\s*\([^)]*\+[^)]*\)",
                r"file\s*\([^)]*\+[^)]*\)",
                r"os\.path\.join\s*\([^)]*input",
                r"Path\s*\([^)]*input"
            ],
            "Deserialization Vulnerabilities": [
                r"pickle\.loads?\s*\(",
                r"cPickle\.loads?\s*\(",
                r"yaml\.load\s*\(",
                r"marshal\.loads?\s*\("
            ],
            "Weak Random Generation": [
                r"random\.random\s*\(\)",
                r"random\.choice\s*\(",
                r"random\.randint\s*\("
            ],
            "Hardcoded Secrets": [
                r"(password|passwd|pwd|secret|api_key|apikey|token|key)\s*=\s*['\"][^'\"]{3,}['\"]",
                r"(PASSWORD|SECRET|API_KEY|APIKEY|TOKEN|KEY)\s*=\s*['\"][^'\"]{3,}['\"]"
            ],
            "Debug Mode Issues": [
                r"debug\s*=\s*True",
                r"DEBUG\s*=\s*True",
                r"app\.run\([^)]*debug\s*=\s*True"
            ],
            "LDAP Injection": [
                r"ldap\.search\s*\([^)]*\+",
                r"ldap3\.search\s*\([^)]*\+"
            ],
            "XML Vulnerabilities": [
                r"xml\.etree\.ElementTree\.parse",
                r"xml\.dom\.minidom\.parse",
                r"lxml\.etree\.parse"
            ]
        },
        'Java': {
            "SQL Injection": [
                r"Statement\s*\.\s*execute\s*\([^)]*\+",
                r"prepareStatement\s*\([^)]*\+",
                r"(SELECT|INSERT|UPDATE|DELETE).*\+.*"
            ],
            "Command Injection": [
                r"Runtime\.getRuntime\(\)\.exec\s*\(",
                r"ProcessBuilder\s*\([^)]*\+",
                r"System\.exec\s*\("
            ],
            "Code Injection": [
                r"ScriptEngine.*eval\s*\(",
                r"Compiler\.compile\s*\(",
                r"Class\.forName\s*\("
            ],
            "Deserialization": [
                r"ObjectInputStream.*readObject\s*\(\)",
                r"XMLDecoder.*readObject\s*\(\)"
            ],
            "Hardcoded Credentials": [
                r"(password|passwd|pwd|secret|api_key|apikey|token|key)\s*=\s*\"[^\"]{3,}\"",
                r"(PASSWORD|SECRET|API_KEY|APIKEY|TOKEN|KEY)\s*=\s*\"[^\"]{3,}\""
            ]
        },
        'C': {
            "Buffer Overflow": [
                r"\bstrcpy\s*\(",
                r"\bstrcat\s*\(",
                r"\bsprintf\s*\(",
                r"\bgets\s*\("
            ],
            "Format String": [
                r"printf\s*\([^)]*%[^)]*\)",
                r"fprintf\s*\([^)]*%[^)]*\)",
                r"sprintf\s*\([^)]*%[^)]*\)"
            ],
            "Memory Issues": [
                r"\bmalloc\s*\(",
                r"\bfree\s*\(",
                r"\bcalloc\s*\(",
                r"\brealloc\s*\("
            ]
        },
        'HTML': {
            "XSS Vulnerabilities": [
                r"<script[^>]*>.*</script>",
                r"javascript\s*:",
                r"on\w+\s*=\s*['\"][^'\"]*['\"]",
                r"<iframe[^>]*src\s*=\s*['\"]javascript:",
                r"<img[^>]*src\s*=\s*['\"]javascript:"
            ],
            "Insecure Links": [
                r"<a[^>]*href\s*=\s*['\"]javascript:",
                r"<a[^>]*href\s*=\s*['\"]data:",
                r"target\s*=\s*['\"]_blank['\"][^>]*(?!rel\s*=\s*['\"][^'\"]*noopener)"
            ],
            "Form Security Issues": [
                r"<form[^>]*method\s*=\s*['\"]get['\"][^>]*>.*<input[^>]*type\s*=\s*['\"]password['\"]",
                r"<input[^>]*type\s*=\s*['\"]password['\"][^>]*(?!autocomplete\s*=\s*['\"]off['\"])"
            ],
            "Iframe Security": [
                r"<iframe[^>]*(?!sandbox\s*=)",
                r"<iframe[^>]*src\s*=\s*['\"]http://",
                r"<embed[^>]*src\s*=",
                r"<object[^>]*data\s*="
            ],
            "Missing Security Headers": [
                r"<meta[^>]*http-equiv\s*=\s*['\"]Content-Security-Policy['\"]",
                r"<meta[^>]*http-equiv\s*=\s*['\"]X-Frame-Options['\"]"
            ]
        },
        'CSS': {
            "CSS Injection": [
                r"expression\s*\(",
                r"javascript\s*:",
                r"@import\s*['\"]javascript:",
                r"behavior\s*:"
            ],
            "Data Exfiltration": [
                r"@import\s*url\(",
                r"background(-image)?\s*:\s*url\(",
                r"content\s*:\s*url\("
            ]
        },
        'Unknown': {
            "Generic Security Issues": [
                r"(password|passwd|pwd|secret|api_key|apikey|token|key)\s*[:=]\s*['\"][^'\"]{3,}['\"]",
                r"(SELECT|INSERT|UPDATE|DELETE).*[+%].*",
                r"\beval\s*\(",
                r"\bexec\s*\(",
                r"<script[^>]*>.*</script>",
                r"javascript\s*:"
            ]
        }
    }

def scan_code_file(file_path, language):
    """Enhanced vulnerability scanner for multiple languages"""
    vulnerabilities = []
    patterns = get_vulnerability_patterns()
    
    try:
        # Try different encodings to handle various file types
        encodings = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']
        content = None
        
        for encoding in encodings:
            try:
                with open(file_path, 'r', encoding=encoding, errors='ignore') as file:
                    content = file.read()
                    break
            except UnicodeDecodeError:
                continue
        
        if content is None:
            # If all encodings fail, try binary mode and decode with errors='ignore'
            with open(file_path, 'rb') as file:
                content = file.read().decode('utf-8', errors='ignore')
        
        lines = content.splitlines()
        
        # Get patterns for the detected language, fallback to Unknown if not found
        lang_patterns = patterns.get(language, patterns.get('Unknown', {}))
        
        for line_number, line in enumerate(lines, start=1):
            line_stripped = line.strip()
            
            # Skip empty lines and comments
            if not line_stripped or line_stripped.startswith(('#', '//', '/*', '<!--', '*', '--')):
                continue
            
            for vuln_category, pattern_list in lang_patterns.items():
                for pattern in pattern_list:
                    try:
                        if re.search(pattern, line, re.IGNORECASE | re.MULTILINE):
                            vulnerabilities.append({
                                "vulnerability": vuln_category,
                                "line": line_number,
                                "code": line_stripped[:200] + ('...' if len(line_stripped) > 200 else ''),  # Truncate long lines
                                "severity": get_severity(vuln_category),
                                "description": get_vulnerability_description(vuln_category),
                                "recommendation": get_vulnerability_recommendation(vuln_category)
                            })
                            break  # Only report first match per line per category
                    except re.error:
                        continue  # Skip invalid regex patterns
                        
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
    
    return vulnerabilities

def get_severity(vulnerability_type):
    """Assign severity levels to vulnerabilities"""
    high_severity = [
        "SQL Injection", "Command Injection", "Code Injection", 
        "File Inclusion", "LDAP Injection", "XML Injection",
        "Buffer Overflow", "Deserialization"
    ]
    medium_severity = [
        "XSS (Cross-Site Scripting)", "Session Security Issues", 
        "File Upload Vulnerabilities", "Deserialization Vulnerabilities",
        "Unsafe Redirects", "Prototype Pollution", "Format String",
        "Memory Issues"
    ]
    
    if any(high in vulnerability_type for high in high_severity):
        return "High"
    elif any(medium in vulnerability_type for medium in medium_severity):
        return "Medium"
    else:
        return "Low"

def get_vulnerability_description(vulnerability_type):
    """Get detailed description for vulnerability types"""
    descriptions = {
        "SQL Injection": "Allows attackers to interfere with database queries and potentially access, modify, or delete data",
        "XSS (Cross-Site Scripting)": "Enables injection of malicious scripts that execute in users' browsers",
        "Command Injection": "Allows execution of arbitrary system commands on the host server",
        "File Inclusion": "Permits inclusion of files from arbitrary locations, potentially exposing sensitive data",
        "Code Injection": "Allows execution of arbitrary code in the application context",
        "Weak Cryptography": "Uses outdated or weak cryptographic functions that can be easily broken",
        "Hardcoded Credentials": "Contains sensitive information directly in the source code",
        "Information Disclosure": "May leak sensitive system or application information to attackers",
        "Session Security Issues": "Vulnerabilities in session management that could lead to session hijacking",
        "File Upload Vulnerabilities": "Insecure file upload handling that could allow malicious file execution",
        "LDAP Injection": "Allows manipulation of LDAP queries to gain unauthorized access",
        "XML Injection": "Enables injection of malicious XML content",
        "Buffer Overflow": "Memory corruption vulnerability that can lead to code execution",
        "Format String": "Vulnerability in format string functions that can lead to information disclosure or code execution",
        "Memory Issues": "Potential memory management problems that could lead to crashes or vulnerabilities",
        "Deserialization": "Unsafe deserialization that can lead to code execution",
        "Generic Security Issues": "Potential security concerns identified in the code"
    }
    return descriptions.get(vulnerability_type, "Security risk identified in the code")

def get_vulnerability_recommendation(vulnerability_type):
    """Get recommendations for fixing vulnerabilities"""
    recommendations = {
        "SQL Injection": "Use parameterized queries or prepared statements instead of string concatenation",
        "XSS (Cross-Site Scripting)": "Sanitize and validate all user inputs, use output encoding",
        "Command Injection": "Avoid system calls with user input; use safe APIs and input validation",
        "File Inclusion": "Validate file paths and use whitelisting for allowed files",
        "Code Injection": "Never use eval() or similar functions with user input",
        "Weak Cryptography": "Use strong, modern cryptographic functions (bcrypt, Argon2, etc.)",
        "Hardcoded Credentials": "Use environment variables or secure configuration files",
        "Information Disclosure": "Remove debug information and sensitive data from production code",
        "Session Security Issues": "Implement proper session management and validation",
        "File Upload Vulnerabilities": "Validate file types, scan uploads, and restrict execution permissions",
        "Buffer Overflow": "Use safe string functions like strncpy, strncat, or modern languages with bounds checking",
        "Format String": "Use format strings with proper argument validation and avoid user-controlled format strings",
        "Memory Issues": "Use memory-safe practices, check return values, and consider using smart pointers or garbage-collected languages",
        "Deserialization": "Validate serialized data, use safe serialization libraries, and avoid deserializing untrusted data"
    }
    return recommendations.get(vulnerability_type, "Review and secure this code pattern")

def generate_detailed_report(vulnerabilities, filename, language, file_hash):
    """Generate comprehensive security report"""
    # Calculate statistics
    total_vulns = len(vulnerabilities)
    high_count = len([v for v in vulnerabilities if v["severity"] == "High"])
    medium_count = len([v for v in vulnerabilities if v["severity"] == "Medium"])
    low_count = len([v for v in vulnerabilities if v["severity"] == "Low"])
    
    # Calculate risk score (weighted)
    risk_score = (high_count * 10) + (medium_count * 5) + (low_count * 1)
    max_possible_score = 100
    risk_percentage = min((risk_score / max_possible_score) * 100, 100)
    
    # Determine risk level
    if risk_percentage >= 70:
        risk_level = "Critical"
    elif risk_percentage >= 40:
        risk_level = "High"
    elif risk_percentage >= 20:
        risk_level = "Medium"
    else:
        risk_level = "Low"
    
    # Group vulnerabilities by type
    vuln_categories = {}
    for vuln in vulnerabilities:
        category = vuln["vulnerability"]
        if category not in vuln_categories:
            vuln_categories[category] = []
        vuln_categories[category].append(vuln)
    
    report = {
        "scan_metadata": {
            "filename": filename,
            "language": language,
            "file_hash": file_hash,
            "scan_date": datetime.now().isoformat(),
            "scan_version": "1.0.0"
        },
        "summary": {
            "total_vulnerabilities": total_vulns,
            "high_severity": high_count,
            "medium_severity": medium_count,
            "low_severity": low_count,
            "risk_score": risk_score,
            "risk_percentage": round(risk_percentage, 2),
            "risk_level": risk_level
        },
        "vulnerability_categories": vuln_categories,
        "detailed_findings": vulnerabilities,
        "recommendations": {
            "immediate_actions": [],
            "security_improvements": [],
            "best_practices": []
        }
    }
    
    # Add specific recommendations based on findings
    if high_count > 0:
        report["recommendations"]["immediate_actions"].append(
            "Address all HIGH severity vulnerabilities immediately"
        )
    if medium_count > 0:
        report["recommendations"]["security_improvements"].append(
            "Review and fix MEDIUM severity issues"
        )
    
    # Add general recommendations
    report["recommendations"]["best_practices"] = [
        "Implement input validation and sanitization",
        "Use parameterized queries for database operations",
        "Employ proper output encoding",
        "Regular security code reviews",
        "Use static analysis tools in CI/CD pipeline",
        "Keep dependencies up to date"
    ]
    
    return report

@app.route('/')
def index():
    """Main landing page"""
    return render_template('index.html')

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    """Handle file upload and scanning - More permissive version"""
    if request.method == 'POST':
        try:
            # Validate request
            if 'file' not in request.files:
                return jsonify({"error": "No file provided"}), 400