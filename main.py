from flask import Flask, request, render_template, redirect, url_for, jsonify, send_file, session
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
        'php': 'PHP', 'js': 'JavaScript', 'jsx': 'JavaScript (React)', 'ts': 'TypeScript',
        'tsx': 'TypeScript (React)', 'html': 'HTML', 'htm': 'HTML', 'py': 'Python',
        'css': 'CSS', 'json': 'JSON', 'xml': 'XML', 'java': 'Java', 'aspx': 'ASP.NET',
        'jsp': 'JSP', 'txt': 'Text File', 'c': 'C', 'cpp': 'C++', 'cs': 'C#'
    }
    return language_map.get(ext, 'Unknown')

def get_vulnerability_patterns():
    """Return comprehensive vulnerability patterns for different languages"""
    return {
        'PHP': {
            "SQL Injection": [
                r"\$_(GET|POST|REQUEST|COOKIE)\s*\[.*?\].*?(SELECT|INSERT|UPDATE|DELETE)",
                r"(mysql_query|mysqli_query|pg_query)\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)",
                r"(SELECT|INSERT|UPDATE|DELETE)[^;]*\$_(GET|POST|REQUEST|COOKIE)"
            ],
            "XSS (Cross-Site Scripting)": [
                r"echo\s+\$_(GET|POST|REQUEST|COOKIE)",
                r"print\s+\$_(GET|POST|REQUEST|COOKIE)",
                r"printf?\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)"
            ],
            "Command Injection": [
                r"(exec|shell_exec|system|passthru|popen)\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)",
                r"backticks.*\$_(GET|POST|REQUEST|COOKIE)"
            ],
            "File Inclusion": [
                r"(include|require|include_once|require_once)\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)"
            ],
            "Code Injection": [
                r"eval\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)"
            ],
            "Hardcoded Credentials": [
                r"(password|passwd|pwd|secret|api_key|apikey|token|key)\s*=\s*['\"][a-zA-Z0-9@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?~`!]{3,}['\"]"
            ]
        },
        'JavaScript': {
            "XSS (Cross-Site Scripting)": [
                r"\.innerHTML\s*=",
                r"document\.write\s*\(",
                r"\.outerHTML\s*="
            ],
            "Code Injection": [
                r"\beval\s*\(",
                r"Function\s*\(",
                r"setTimeout\s*\([^,)]*['\"][^'\"]*['\"]",
                r"setInterval\s*\([^,)]*['\"][^'\"]*['\"]"
            ],
            "Unsafe Redirects": [
                r"window\.location\s*=",
                r"location\.href\s*=",
                r"location\.replace\s*\("
            ],
            "Hardcoded Secrets": [
                r"(api_key|apikey|secret|token|password)\s*[:=]\s*['\"][a-zA-Z0-9@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?~`!]{5,}['\"]"
            ]
        },
        'Python': {
            "SQL Injection": [
                r"cursor\.execute\s*\([^)]*%[^)]*\)",
                r"(SELECT|INSERT|UPDATE|DELETE)[^;]*\+",
                r"\.execute\s*\([^)]*\.format\s*\("
            ],
            "Command Injection": [
                r"os\.system\s*\(",
                r"subprocess\.(call|run|Popen)\s*\(",
                r"os\.popen\s*\("
            ],
            "Code Injection": [
                r"\beval\s*\(",
                r"\bexec\s*\(",
                r"compile\s*\("
            ],
            "Hardcoded Secrets": [
                r"(password|passwd|pwd|secret|api_key|apikey|token|key)\s*=\s*['\"][a-zA-Z0-9@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?~`!]{3,}['\"]"
            ]
        },
        'Java': {
            "SQL Injection": [
                r"Statement\s*\.\s*execute\s*\([^)]*\+",
                r"(SELECT|INSERT|UPDATE|DELETE)[^;]*\+",
                r"createStatement\s*\(\s*\)\.execute"
            ],
            "Command Injection": [
                r"Runtime\.getRuntime\(\)\.exec\s*\(",
                r"ProcessBuilder\s*\("
            ],
            "Hardcoded Credentials": [
                r"(password|passwd|pwd|secret|api_key|apikey|token|key)\s*=\s*\"[a-zA-Z0-9@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?~`!]{3,}\""
            ]
        },
        'HTML': {
            "XSS Vulnerabilities": [
                r"<script[^>]*>",
                r"javascript\s*:",
                r"on\w+\s*=\s*['\"][^'\"]*['\"]"
            ],
            "Insecure Links": [
                r"<a[^>]*href\s*=\s*['\"]javascript:",
                r"target\s*=\s*['\"]_blank['\"][^>]*(?!rel\s*=\s*['\"][^'\"]*noopener)"
            ]
        },
        'Unknown': {
            "Generic Security Issues": [
                r"(password|passwd|pwd|secret|api_key|apikey|token|key)\s*[:=]\s*['\"][a-zA-Z0-9@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?~`!]{3,}['\"]",
                r"(SELECT|INSERT|UPDATE|DELETE).*[+%]",
                r"\beval\s*\(",
                r"<script[^>]*>"
            ]
        }
    }

def scan_code_file(file_path, language):
    """Enhanced vulnerability scanner for multiple languages"""
    vulnerabilities = []
    patterns = get_vulnerability_patterns()
    
    try:
        # Try different encodings
        content = None
        encodings_to_try = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']
        
        for encoding in encodings_to_try:
            try:
                with open(file_path, 'r', encoding=encoding) as file:
                    content = file.read()
                break
            except (UnicodeDecodeError, UnicodeError):
                continue
        
        # If all encodings fail, try binary mode
        if content is None:
            with open(file_path, 'rb') as file:
                raw_content = file.read()
                content = raw_content.decode('utf-8', errors='replace')
        
        if not content:
            print(f"Could not read content from {file_path}")
            return vulnerabilities
        
        lines = content.splitlines()
        lang_patterns = patterns.get(language, patterns.get('Unknown', {}))
        
        print(f"Scanning {len(lines)} lines for {language} vulnerabilities...")
        print(f"Available patterns: {list(lang_patterns.keys())}")
        
        for line_number, line in enumerate(lines, start=1):
            line_stripped = line.strip()
            
            # Skip empty lines and comments
            if not line_stripped:
                continue
            
            # Skip common comment patterns
            comment_patterns = ['#', '//', '/*', '<!--', '*', '--', '\'\'\'', '"""']
            if any(line_stripped.startswith(pattern) for pattern in comment_patterns):
                continue
            
            # Check each vulnerability pattern
            for vuln_category, pattern_list in lang_patterns.items():
                for pattern in pattern_list:
                    try:
                        if re.search(pattern, line, re.IGNORECASE):
                            vulnerability = {
                                "vulnerability": vuln_category,
                                "line": line_number,
                                "code": line_stripped[:200] + ('...' if len(line_stripped) > 200 else ''),
                                "severity": get_severity(vuln_category),
                                "description": get_vulnerability_description(vuln_category),
                                "recommendation": get_vulnerability_recommendation(vuln_category)
                            }
                            vulnerabilities.append(vulnerability)
                            print(f"Found {vuln_category} at line {line_number}: {line_stripped[:50]}...")
                            break  # Only report one vulnerability per line per category
                    except re.error as e:
                        print(f"Regex error with pattern {pattern}: {e}")
                        continue
                        
    except Exception as e:
        print(f"Error scanning file {file_path}: {e}")
    
    print(f"Total vulnerabilities found: {len(vulnerabilities)}")
    return vulnerabilities

def get_severity(vulnerability_type):
    """Assign severity levels to vulnerabilities"""
    high_severity = ["SQL Injection", "Command Injection", "Code Injection", "File Inclusion"]
    medium_severity = ["XSS (Cross-Site Scripting)", "Unsafe Redirects", "XSS Vulnerabilities", "Insecure Links"]
    
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
        "Hardcoded Credentials": "Contains sensitive information directly in the source code",
        "Hardcoded Secrets": "Contains sensitive information directly in the source code",
        "Unsafe Redirects": "Redirects that can be manipulated to redirect users to malicious sites",
        "XSS Vulnerabilities": "HTML/JavaScript code that can be exploited for cross-site scripting attacks",
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
        "Hardcoded Credentials": "Use environment variables or secure configuration files",
        "Hardcoded Secrets": "Use environment variables or secure configuration files",
        "Unsafe Redirects": "Validate redirect URLs and use whitelist of allowed domains",
        "XSS Vulnerabilities": "Remove inline JavaScript and validate all HTML content"
    }
    return recommendations.get(vulnerability_type, "Review and secure this code pattern")

def generate_security_recommendations(vulnerabilities):
    """Generate security recommendations based on found vulnerabilities"""
    recommendations = {
        "immediate_actions": [],
        "best_practices": [
            "Implement input validation and sanitization",
            "Use parameterized queries for database operations",
            "Keep dependencies and frameworks up to date",
            "Implement proper error handling and logging",
            "Use HTTPS for all communications",
            "Implement proper authentication and authorization",
            "Regular security testing and code reviews"
        ]
    }
    
    vuln_types = set()
    high_severity_count = 0
    
    for vuln in vulnerabilities:
        vuln_types.add(vuln["vulnerability"])
        if vuln["severity"] == "High":
            high_severity_count += 1
    
    # Add immediate actions based on vulnerabilities found
    if "SQL Injection" in vuln_types:
        recommendations["immediate_actions"].append("Fix SQL injection vulnerabilities immediately - use prepared statements")
    
    if "Command Injection" in vuln_types:
        recommendations["immediate_actions"].append("Remove or secure command execution code")
    
    if "Code Injection" in vuln_types:
        recommendations["immediate_actions"].append("Remove eval() and similar functions or add strict input validation")
    
    if "Hardcoded Credentials" in vuln_types or "Hardcoded Secrets" in vuln_types:
        recommendations["immediate_actions"].append("Move hardcoded secrets to environment variables or secure configuration")
    
    if high_severity_count > 0:
        recommendations["immediate_actions"].append(f"Address {high_severity_count} high-severity vulnerabilities first")
    
    return recommendations

def generate_detailed_report(vulnerabilities, filename, language, file_hash):
    """Generate comprehensive security report"""
    total_vulns = len(vulnerabilities)
    high_count = len([v for v in vulnerabilities if v["severity"] == "High"])
    medium_count = len([v for v in vulnerabilities if v["severity"] == "Medium"])
    low_count = len([v for v in vulnerabilities if v["severity"] == "Low"])
    
    risk_score = (high_count * 10) + (medium_count * 5) + (low_count * 1)
    risk_percentage = min((risk_score / 100) * 100, 100) if risk_score > 0 else 0
    
    if risk_percentage >= 70:
        risk_level = "Critical"
    elif risk_percentage >= 40:
        risk_level = "High"
    elif risk_percentage >= 20:
        risk_level = "Medium"
    else:
        risk_level = "Low"
    
    # Group vulnerabilities by category
    vuln_categories = {}
    for vuln in vulnerabilities:
        category = vuln["vulnerability"]
        if category not in vuln_categories:
            vuln_categories[category] = []
        vuln_categories[category].append(vuln)
    
    # Generate recommendations
    recommendations = generate_security_recommendations(vulnerabilities)
    
    return {
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
        "recommendations": recommendations
    }

@app.route('/')
def index():
    """Main landing page"""
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    """Handle file upload and scanning"""
    if request.method == 'POST':
        try:
            if 'file' not in request.files:
                return jsonify({"error": "No file provided"}), 400
            
            file = request.files['file']
            if file.filename == '':
                return jsonify({"error": "No file selected"}), 400
            
            if not allowed_file(file.filename):
                return jsonify({"error": "File type not allowed"}), 400
            
            # Read file content
            file_content = file.read()
            file.seek(0)  # Reset file pointer
            
            # Security check
            is_safe, safety_message = is_safe_file(file.filename, file_content)
            if not is_safe:
                return jsonify({"error": safety_message}), 400
            
            # Save file
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            # Detect language and get file hash
            language = detect_language(filename)
            file_hash = get_file_hash(file_path)
            
            print(f"Processing file: {filename}, Language: {language}")
            
            # Scan for vulnerabilities
            vulnerabilities = scan_code_file(file_path, language)
            
            # Generate detailed report
            report = generate_detailed_report(vulnerabilities, filename, language, file_hash)
            
            # Store report in session
            session['scan_report'] = report
            
            # Clean up uploaded file
            try:
                os.remove(file_path)
            except Exception:
                pass
            
            # Redirect to results page
            return redirect(url_for('results'))
            
        except RequestEntityTooLarge:
            return jsonify({"error": "File too large"}), 413
        except Exception as e:
            print(f"Upload error: {e}")
            return jsonify({"error": f"Upload failed: {str(e)}"}), 500
    
    return render_template('upload.html')

@app.route('/result')
@app.route('/results')
def results():
    """Display scan results"""
    if 'scan_report' not in session:
        return redirect(url_for('index'))
    
    report = session['scan_report']
    return render_template('result.html', report=report)

@app.route('/api/scan', methods=['POST'])
def api_scan():
    """API endpoint for code scanning"""
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file provided"}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "No file selected"}), 400
        
        file_content = file.read()
        file.seek(0)
        
        is_safe, safety_message = is_safe_file(file.filename, file_content)
        if not is_safe:
            return jsonify({"error": safety_message}), 400
        
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        language = detect_language(filename)
        file_hash = get_file_hash(file_path)
        vulnerabilities = scan_code_file(file_path, language)
        report = generate_detailed_report(vulnerabilities, filename, language, file_hash)
        
        try:
            os.remove(file_path)
        except Exception:
            pass
        
        return jsonify(report)
        
    except Exception as e:
        return jsonify({"error": f"Scan failed: {str(e)}"}), 500

@app.errorhandler(413)
def too_large(e):
    return jsonify({"error": "File too large"}), 413

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':

    app.run(debug=True, host='127.0.0.1', port=80)