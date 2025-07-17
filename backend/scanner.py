import os
import re
import xml.etree.ElementTree as ET
from collections import defaultdict
import hashlib
import math

class VulnerabilityDeduplicator:
    def __init__(self):
        self.seen_vulns = set()

    def add_vulnerability(self, vuln):
        vuln_hash = hashlib.md5(
            f"{vuln['title']}{vuln.get('file', '')}{vuln.get('line', '')}{vuln.get('poc', '')}".encode()
        ).hexdigest()
        if vuln_hash not in self.seen_vulns:
            self.seen_vulns.add(vuln_hash)
            return True
        return False

def analyze_apk(decompiled_path):
    deduplicator = VulnerabilityDeduplicator()
    vulnerabilities = []
    all_vulns = []
    all_vulns.extend(check_manifest_issues(decompiled_path))
    all_vulns.extend(check_hardcoded_secrets(decompiled_path))
    all_vulns.extend(check_webview_issues(decompiled_path))
    all_vulns.extend(check_network_issues(decompiled_path))
    all_vulns.extend(check_weak_crypto(decompiled_path))
    all_vulns.extend(check_insecure_storage(decompiled_path))
    all_vulns.extend(check_sensitive_logs(decompiled_path))
    all_vulns.extend(check_dynamic_code_loading(decompiled_path))
    all_vulns.extend(check_ssl_validation_bypass(decompiled_path))
    all_vulns.extend(check_dangerous_permissions(decompiled_path))
    all_vulns.extend(check_sql_injection(decompiled_path))
    all_vulns.extend(check_clipboard_access(decompiled_path))
    all_vulns.extend(check_runtime_command_exec(decompiled_path))
    all_vulns.extend(check_file_uri_exposure(decompiled_path))
    all_vulns.extend(check_screenshot_allowed(decompiled_path))
    all_vulns.extend(check_webview_xss_risk(decompiled_path))
    all_vulns.extend(check_toast_leaks(decompiled_path))
    all_vulns.extend(check_path_traversal(decompiled_path))
    all_vulns.extend(check_insecure_deserialization(decompiled_path))
    all_vulns.extend(check_intent_redirection(decompiled_path))
    all_vulns.extend(check_insecure_content_provider(decompiled_path))
    all_vulns.extend(check_fragment_injection(decompiled_path))
    all_vulns.extend(check_tapjacking(decompiled_path))
    all_vulns.extend(check_missing_protection_level(decompiled_path))

    for vuln in all_vulns:
        if deduplicator.add_vulnerability(vuln):
            vulnerabilities.append(vuln)

    severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}
    vulnerabilities.sort(key=lambda v: severity_order.get(v['severity'], 99))

    manifest_path = os.path.join(decompiled_path, 'AndroidManifest.xml')
    app_name, package_name = get_app_details(manifest_path)

    return {
        "appName": app_name,
        "packageName": package_name,
        "vulnerabilities": vulnerabilities,
        "summary": {
            "total": len(vulnerabilities),
            "critical": len([v for v in vulnerabilities if v['severity'] == 'Critical']),
            "high": len([v for v in vulnerabilities if v['severity'] == 'High']),
            "medium": len([v for v in vulnerabilities if v['severity'] == 'Medium']),
            "low": len([v for v in vulnerabilities if v['severity'] == 'Low']),
            "info": len([v for v in vulnerabilities if v['severity'] == 'Info']),
        }
    }

def get_app_details(manifest_path):
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        package_name = root.attrib.get('package', 'N/A')
        app_tag = root.find('application')
        if app_tag is not None:
            ns = {'android': 'http://schemas.android.com/apk/res/android'}
            app_name = app_tag.attrib.get(f"{{{ns['android']}}}label", package_name)
            if app_name.startswith('@string/'):
                app_name = package_name
        else:
            app_name = package_name
        return app_name, package_name
    except Exception:
        return "UnknownApp", "com.unknown.package"

def check_hardcoded_secrets(path):
    found = []
    patterns = {
        'Google API Key': r'AIza[0-9A-Za-z\\-_]{35}',
        'AWS Access Key': r'AKIA[0-9A-Z]{16}',
        'Firebase URL': r'https://[a-z0-9-]+\\.firebaseio\\.com',
        'Private Key': r'-----BEGIN (?:RSA|EC|PGP|DSA) PRIVATE KEY-----',
        'JWT Token': r'eyJ[A-Za-z0-9\\-_=]+\\.[A-Za-z0-9\\-_=]+\\.?[A-Za-z0-9\\-_.+/=]*',
        'Generic API Key': r'["\"](?:api_key|apikey|access_token|client_secret)["\"]?\s*[:=]\s*["\"][a-zA-Z0-9_\\-]{16,}[\'"]'
    }
    ignore_patterns = [r'example', r'test', r'demo', r'dummy', r'fake', r'placeholder']
    for root, _, files in os.walk(path):
        for file in files:
            if file.endswith(('.java', '.kt', '.smali', '.xml', '.json', '.properties')):
                fpath = os.path.join(root, file)
                if any(skip in fpath for skip in ['build/', 'gen/', 'R.java', '.gradle']):
                    continue
                try:
                    with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for name, pattern in patterns.items():
                            for match in re.finditer(pattern, content):
                                matched_text = match.group(0)
                                if not any(re.search(ignore, matched_text, re.IGNORECASE) for ignore in ignore_patterns):
                                    found.append({
                                        "severity": "Critical",
                                        "title": f"Hardcoded Secret: {name}",
                                        "description": f"Found a hardcoded {name.lower()} in the source code. Attackers can decompile the APK and extract this secret.",
                                        "file": os.path.relpath(fpath, path),
                                        "line": content.count('\n', 0, match.start()) + 1,
                                        "poc": f"Matched: `{matched_text[:100]}...`",
                                        "mitigation": "Store secrets on a secure server-side environment and fetch them at runtime. For client-side secrets, use the Android Keystore system.",
                                        "impact": "Compromise of the associated service, data breaches, and potential financial loss."
                                    })
                except Exception:
                    continue
    return found

def check_manifest_issues(path):
    found = []
    manifest_path = os.path.join(path, 'AndroidManifest.xml')
    if not os.path.exists(manifest_path):
        return found
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        ns = {'android': 'http://schemas.android.com/apk/res/android'}
        app_tag = root.find('application')
        if app_tag is None:
            return found
        if app_tag.attrib.get(f"{{{ns['android']}}}debuggable") == 'true':
            found.append({
                "severity": "High",
                "title": "Application is Debuggable",
                "description": "The application is set to be debuggable, which can expose it to reverse engineering and runtime manipulation.",
                "file": "AndroidManifest.xml",
                "poc": 'android:debuggable="true" in the <application> tag.',
                "mitigation": "Ensure `android:debuggable` is set to `false` in production builds.",
                "impact": "Attackers can attach a debugger to the app, inspect memory, execute code, and extract sensitive information."
            })
        for component_type in ['activity', 'service', 'receiver', 'provider']:
            for component in app_tag.findall(component_type):
                name = component.attrib.get(f"{{{ns['android']}}}name", 'Unknown')
                exported = component.attrib.get(f"{{{ns['android']}}}exported")
                permission = component.attrib.get(f"{{{ns['android']}}}permission")
                has_intent_filter = component.find('intent-filter') is not None
                is_exported = exported == 'true' or (exported != 'false' and has_intent_filter)
                if is_exported and not permission:
                    found.append({
                        "severity": "High",
                        "title": f"Unprotected Exported {component_type.capitalize()}",
                        "description": f"The {component_type} '{name}' is exported but not protected by a permission.",
                        "file": "AndroidManifest.xml",
                        "poc": f"Component: `{name}` is exported without a permission.",
                        "mitigation": "Set `android:exported=\"false\"` for private components or protect exported components with a custom permission.",
                        "impact": "Malicious apps can interact with this component, potentially leading to data leakage, denial of service, or other vulnerabilities."
                    })
        if app_tag.attrib.get(f"{{{ns['android']}}}allowBackup") != 'false':
            found.append({
                "severity": "Medium",
                "title": "Application Data Backup is Allowed",
                "description": "The application's data can be backed up via `adb backup`, which could expose sensitive information.",
                "file": "AndroidManifest.xml",
                "poc": 'android:allowBackup is not explicitly set to "false".',
                "mitigation": "Set `android:allowBackup=\"false\"` if the app handles sensitive data.",
                "impact": "An attacker with physical access to the device could back up the app's data and extract sensitive information."
            })
        if app_tag.attrib.get(f"{{{ns['android']}}}usesCleartextTraffic") == 'true':
            found.append({
                "severity": "High",
                "title": "Cleartext HTTP Traffic is Permitted",
                "description": "The application explicitly permits cleartext HTTP traffic, which is insecure.",
                "file": "AndroidManifest.xml",
                "poc": 'android:usesCleartextTraffic="true" in the <application> tag.',
                "mitigation": "Set `android:usesCleartextTraffic=\"false\"` and use HTTPS for all network communication.",
                "impact": "Sensitive data sent over the network can be intercepted by attackers (Man-in-the-Middle attack)."
            })
    except ET.ParseError:
        pass
    return found

def check_network_issues(path):
    found = []
    http_pattern = r'(URL|URI)\\s*\\(\\s*"\\s*http://'
    for root, _, files in os.walk(path):
        for file in files:
            if file.endswith(('.java', '.kt')):
                fpath = os.path.join(root, file)
                try:
                    with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for match in re.finditer(http_pattern, content):
                            found.append({
                                "severity": "High",
                                "title": "Insecure HTTP Communication",
                                "description": "The application uses an insecure HTTP connection, which can expose data to interception.",
                                "file": os.path.relpath(fpath, path),
                                "line": content.count('\n', 0, match.start()) + 1,
                                "poc": f"Insecure URL call: `{match.group(0)}`",
                                "mitigation": "Use HTTPS for all network communications. Implement certificate pinning for added security.",
                                "impact": "Man-in-the-middle attacks, allowing attackers to intercept, read, and modify network traffic."
                            })
                except Exception:
                    continue
    return found

def check_webview_issues(path):
    found = []
    patterns = {
        'javascript_enabled': (r'\\.setJavaScriptEnabled\\s*\\(\\s*true\\s*\\)', "Medium", "WebView JavaScript Enabled"),
        'file_access': (r'\\.setAllowFileAccess\\s*\\(\\s*true\\s*\\)', "Medium", "WebView File Access Enabled"),
        'javascript_interface': (r'\\.addJavascriptInterface\\s*\\(', "High", "WebView JavaScript Interface Exposed"),
    }
    for root, _, files in os.walk(path):
        for file in files:
            if file.endswith(('.java', '.kt')):
                fpath = os.path.join(root, file)
                try:
                    with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for issue, (pattern, severity, title) in patterns.items():
                            for match in re.finditer(pattern, content):
                                found.append({
                                    "severity": severity,
                                    "title": title,
                                    "description": "Insecure WebView setting detected.",
                                    "file": os.path.relpath(fpath, path),
                                    "line": content.count('\n', 0, match.start()) + 1,
                                    "poc": f"Insecure setting: `{match.group(0)}`",
                                    "mitigation": "Disable insecure WebView settings unless absolutely necessary. Sanitize all data passed to a WebView.",
                                    "impact": "Can lead to Cross-Site Scripting (XSS), local file theft, and Remote Code Execution (RCE)."
                                })
                except Exception:
                    continue
    return found

def check_weak_crypto(path):
    found = []
    patterns = {
        'weak_cipher': (r'Cipher\\.getInstance\\s*\\(\\s*"\\s*(DES|RC4|AES/ECB)', "High", "Weak Encryption Algorithm"),
        'weak_hash': (r'MessageDigest\\.getInstance\\s*\\(\\s*"\\s*(MD5|SHA-1)', "Medium", "Weak Hash Algorithm"),
        'insecure_random': (r'new\\s+Random\\s*\\(', "Low", "Insecure Random Number Generator"),
    }
    for root, _, files in os.walk(path):
        for file in files:
            if file.endswith(('.java', '.kt')):
                fpath = os.path.join(root, file)
                try:
                    with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for issue, (pattern, severity, title) in patterns.items():
                            for match in re.finditer(pattern, content):
                                found.append({
                                    "severity": severity,
                                    "title": title,
                                    "description": "The application uses a weak or insecure cryptographic function.",
                                    "file": os.path.relpath(fpath, path),
                                    "line": content.count('\n', 0, match.start()) + 1,
                                    "poc": f"Weak crypto usage: `{match.group(0)}`",
                                    "mitigation": "Use strong, modern cryptographic algorithms like AES-GCM for encryption, SHA-256 for hashing, and `SecureRandom` for random number generation.",
                                    "impact": "Weak cryptography can be broken, leading to data exposure, tampering, and other security breaches."
                                })
                except Exception:
                    continue
    return found

def check_insecure_storage(path):
    found = []
    patterns = {
        'world_readable': (r'MODE_WORLD_READABLE', "Medium", "World-Readable Storage"),
        'world_writable': (r'MODE_WORLD_WRITABLE', "Medium", "World-Writable Storage"),
        'external_storage': (r'getExternalStorageDirectory|getExternalFilesDir', "Low", "External Storage Usage"),
    }
    for root, _, files in os.walk(path):
        for file in files:
            if file.endswith(('.java', '.kt')):
                fpath = os.path.join(root, file)
                try:
                    with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for issue, (pattern, severity, title) in patterns.items():
                            for match in re.finditer(pattern, content):
                                found.append({
                                    "severity": severity,
                                    "title": title,
                                    "description": "The application uses an insecure data storage method.",
                                    "file": os.path.relpath(fpath, path),
                                    "line": content.count('\n', 0, match.start()) + 1,
                                    "poc": f"Insecure storage call: `{match.group(0)}`",
                                    "mitigation": "Use internal storage (`MODE_PRIVATE`) for sensitive data. Encrypt data before storing it.",
                                    "impact": "Sensitive data can be accessed by other malicious applications on the device."
                                })
                except Exception:
                    continue
    return found

def check_sensitive_logs(path):
    found = []
    sensitive_keywords = ['password', 'passwd', 'pwd', 'token', 'auth', 'key', 'secret', 'credit', 'card', 'cvv', 'pin', 'ssn', 'session', 'jwt']
    log_pattern = r'Log\\.(d|v|i|w|e)\\s*\\([^)]*(' + '|'.join(sensitive_keywords) + r'[^)]*\\)'
    for root, _, files in os.walk(path):
        for file in files:
            if file.endswith(('.java', '.kt')):
                fpath = os.path.join(root, file)
                try:
                    with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for match in re.finditer(log_pattern, content, re.IGNORECASE):
                            found.append({
                                "severity": "Medium",
                                "title": "Sensitive Information in Logs",
                                "description": "The application logs sensitive information, which can be exposed to anyone with access to the device logs.",
                                "file": os.path.relpath(fpath, path),
                                "line": content.count('\n', 0, match.start()) + 1,
                                "poc": f"Sensitive log: `{match.group(0)}`",
                                "mitigation": "Do not log sensitive information. Use logging flags to disable verbose logging in production builds.",
                                "impact": "Exposure of sensitive user data, such as credentials, personal information, and session tokens."
                            })
                except Exception:
                    continue
    return found

def check_dynamic_code_loading(path):
    found = []
    pattern = r'DexClassLoader|PathClassLoader'
    for root, _, files in os.walk(path):
        for file in files:
            if file.endswith(('.java', '.kt')):
                fpath = os.path.join(root, file)
                try:
                    with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for match in re.finditer(pattern, content):
                            found.append({
                                "severity": "High",
                                "title": "Dynamic Code Loading",
                                "description": "The application loads code dynamically, which can be a security risk if the code source is not trusted.",
                                "file": os.path.relpath(fpath, path),
                                "line": content.count('\n', 0, match.start()) + 1,
                                "poc": f"Dynamic loading: `{match.group(0)}`",
                                "mitigation": "Avoid loading code from untrusted sources. If dynamic loading is necessary, verify the signature and integrity of the loaded code.",
                                "impact": "Can lead to the execution of malicious code, granting the attacker full control over the application."
                            })
                except Exception:
                    continue
    return found

def check_ssl_validation_bypass(path):
    found = []
    patterns = [
        r'TrustManager\\s*\[\\s*\]\\s*=\\s*new\\s+TrustManager\\s*\[\\s*\]\\s*{\\s*public\\s+void\\s+checkServerTrusted\\s*\\(',
        r'new\\s+HostnameVerifier\\s*\\(\\s*\\)\\s*{\\s*public\\s+boolean\\s+verify\\s*\\([^)]*\\)\\s*{\\s*return\\s+true;\\s*\\}',
        r'ALLOW_ALL_HOSTNAME_VERIFIER'
    ]
    for root, _, files in os.walk(path):
        for file in files:
            if file.endswith(('.java', '.kt')):
                fpath = os.path.join(root, file)
                try:
                    with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for pattern in patterns:
                            for match in re.finditer(pattern, content):
                                found.append({
                                    "severity": "Critical",
                                    "title": "SSL Validation Bypass",
                                    "description": "The application intentionally bypasses SSL certificate validation, making it vulnerable to Man-in-the-Middle attacks.",
                                    "file": os.path.relpath(fpath, path),
                                    "line": content.count('\n', 0, match.start()) + 1,
                                    "poc": f"SSL bypass code: `{match.group(0)}`",
                                    "mitigation": "Remove the code that bypasses SSL validation. Implement proper certificate pinning.",
                                    "impact": "Attackers can intercept and tamper with all network traffic to and from the application."
                                })
                except Exception:
                    continue
    return found

def check_dangerous_permissions(path):
    return []

def check_sql_injection(path):
    found = []
    pattern = r'rawQuery\\s*\\(\\s*".*?"\\s*\\+\\s*\\w+'
    for root, _, files in os.walk(path):
        for file in files:
            if file.endswith(('.java', '.kt')):
                fpath = os.path.join(root, file)
                try:
                    with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for match in re.finditer(pattern, content):
                            found.append({
                                "severity": "High",
                                "title": "Potential SQL Injection",
                                "description": "The application builds SQL queries using string concatenation with user-provided data, which can lead to SQL injection.",
                                "file": os.path.relpath(fpath, path),
                                "line": content.count('\n', 0, match.start()) + 1,
                                "poc": f"Insecure query: `{match.group(0)}`",
                                "mitigation": "Use parameterized queries (selectionArgs) with `rawQuery` or use the `query` method.",
                                "impact": "Attackers can execute arbitrary SQL commands, allowing them to bypass security, and access, modify, or delete data in the database."
                            })
                except Exception:
                    continue
    return found

def check_clipboard_access(path):
    return []

def check_runtime_command_exec(path):
    found = []
    pattern = r'Runtime\\.getRuntime\\(\\)\\.exec\\('
    for root, _, files in os.walk(path):
        for file in files:
            if file.endswith(('.java', '.kt')):
                fpath = os.path.join(root, file)
                try:
                    with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for match in re.finditer(pattern, content):
                            found.append({
                                "severity": "Critical",
                                "title": "Runtime Command Execution",
                                "description": "The application executes shell commands, which can be dangerous if the command is constructed from user input.",
                                "file": os.path.relpath(fpath, path),
                                "line": content.count('\n', 0, match.start()) + 1,
                                "poc": f"Command execution: `{match.group(0)}`",
                                "mitigation": "Avoid executing shell commands. If necessary, use a safe API and validate all inputs.",
                                "impact": "Can lead to arbitrary code execution with the privileges of the application."
                            })
                except Exception:
                    continue
    return found

def check_file_uri_exposure(path):
    found = []
    pattern = r'Uri\\.fromFile\\('
    for root, _, files in os.walk(path):
        for file in files:
            if file.endswith(('.java', '..kt')):
                fpath = os.path.join(root, file)
                try:
                    with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for match in re.finditer(pattern, content):
                            found.append({
                                "severity": "Medium",
                                "title": "File URI Exposure",
                                "description": "The application uses `file://` URIs, which can lead to `FileUriExposedException` on Android Nougat (API 24) and higher.",
                                "file": os.path.relpath(fpath, path),
                                "line": content.count('\n', 0, match.start()) + 1,
                                "poc": f"File URI usage: `{match.group(0)}`",
                                "mitigation": "Use a `FileProvider` to create `content://` URIs for sharing files.",
                                "impact": "The application may crash on newer Android versions. In some cases, it could lead to information disclosure."
                            })
                except Exception:
                    continue
    return found

def check_screenshot_allowed(path):
    return []

def check_webview_xss_risk(path):
    found = []
    pattern = r'loadUrl\\s*\\(\\s*"\\s*javascript:'
    for root, _, files in os.walk(path):
        for file in files:
            if file.endswith(('.java', '.kt')):
                fpath = os.path.join(root, file)
                try:
                    with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for match in re.finditer(pattern, content):
                            found.append({
                                "severity": "High",
                                "title": "WebView XSS Risk",
                                "description": "The application loads a `javascript:` URI in a WebView, which is a potential XSS vulnerability.",
                                "file": os.path.relpath(fpath, path),
                                "line": content.count('\n', 0, match.start()) + 1,
                                "poc": f"XSS risk: `{match.group(0)}`",
                                "mitigation": "Avoid using `javascript:` URIs. If you need to call JavaScript from Java, use `evaluateJavascript`.",
                                "impact": "Can lead to the execution of malicious JavaScript in the context of the application's web page."
                            })
                except Exception:
                    continue
    return found

def check_toast_leaks(path):
    return []

def check_path_traversal(path):
    found = []
    pattern = r'new\\s+File\\s*\\([^)]*\\+\\s*[^)]*\\)'
    for root, _, files in os.walk(path):
        for file in files:
            if file.endswith(('.java', '.kt')):
                fpath = os.path.join(root, file)
                try:
                    with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for match in re.finditer(pattern, content):
                            found.append({
                                "severity": "High",
                                "title": "Path Traversal",
                                "description": "The application creates file paths by concatenating strings, which could allow an attacker to access arbitrary files.",
                                "file": os.path.relpath(fpath, path),
                                "line": content.count('\n', 0, match.start()) + 1,
                                "poc": f"Insecure file path: `{match.group(0)}`",
                                "mitigation": "Validate all inputs used to construct file paths. Canonicalize the path and check that it is within the expected directory.",
                                "impact": "Attackers could read, write, or delete arbitrary files on the device."
                            })
                except Exception:
                    continue
    return found

def check_insecure_deserialization(path):
    found = []
    pattern = r'ObjectInputStream\\s*\\.readObject\\s*\\('
    for root, _, files in os.walk(path):
        for file in files:
            if file.endswith(('.java', '.kt')):
                fpath = os.path.join(root, file)
                try:
                    with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for match in re.finditer(pattern, content):
                            found.append({
                                "severity": "Critical",
                                "title": "Insecure Deserialization",
                                "description": "The application deserializes data without proper validation, which can lead to remote code execution.",
                                "file": os.path.relpath(fpath, path),
                                "line": content.count('\n', 0, match.start()) + 1,
                                "poc": f"Deserialization call: `{match.group(0)}`",
                                "mitigation": "Avoid deserializing untrusted data. If necessary, use a safe serialization format and implement strict type checking.",
                                "impact": "Can lead to remote code execution, denial of service, and other critical vulnerabilities."
                            })
                except Exception:
                    continue
    return found

def check_intent_redirection(path):
    found = []
    pattern = r'\\(Intent\\) getIntent\\(\\)\\.getParcelableExtra\\(.*?\\)'
    for root, _, files in os.walk(path):
        for file in files:
            if file.endswith(('.java', '.kt')):
                fpath = os.path.join(root, file)
                try:
                    with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for match in re.finditer(pattern, content):
                            found.append({
                                "severity": "High",
                                "title": "Intent Redirection",
                                "description": "The application receives an Intent from an external source and uses it to launch a new component, which can lead to unauthorized actions.",
                                "file": os.path.relpath(fpath, path),
                                "line": content.count('\n', 0, match.start()) + 1,
                                "poc": f"Intent redirection: `{match.group(0)}`",
                                "mitigation": "Validate the sender of the Intent and the data it contains. Do not trust Intents from untrusted sources.",
                                "impact": "A malicious app could trick the user into performing unintended actions, such as sending premium SMS messages or making phone calls."
                            })
                except Exception:
                    continue
    return found

def check_insecure_content_provider(path):
    found = []
    manifest_path = os.path.join(path, 'AndroidManifest.xml')
    if not os.path.exists(manifest_path):
        return found
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        ns = {'android': 'http://schemas.android.com/apk/res/android'}
        app_tag = root.find('application')
        if app_tag is None:
            return found
        for provider in app_tag.findall('provider'):
            name = provider.attrib.get(f"{{{ns['android']}}}name", 'Unknown')
            exported = provider.attrib.get(f"{{{ns['android']}}}exported")
            permission = provider.attrib.get(f"{{{ns['android']}}}permission")
            if exported == 'true' and not permission:
                found.append({
                    "severity": "High",
                    "title": "Insecure Content Provider",
                    "description": f"The content provider '{name}' is exported and not protected by a permission.",
                    "file": "AndroidManifest.xml",
                    "poc": f"Content provider: `{name}` is exported without a permission.",
                    "mitigation": "Set `android:exported=\"false\"` for private content providers or protect exported providers with a permission.",
                    "impact": "Other applications can access or modify the data handled by the content provider."
                })
    except ET.ParseError:
        pass
    return found

def check_fragment_injection(path):
    found = []
    pattern = r'loadFragment\\s*\\(\\s*getIntent\\(\\)\\.getStringExtra\\(.*?\\)\\s*\\)'
    for root, _, files in os.walk(path):
        for file in files:
            if file.endswith(('.java', '.kt')):
                fpath = os.path.join(root, file)
                try:
                    with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for match in re.finditer(pattern, content):
                            found.append({
                                "severity": "High",
                                "title": "Fragment Injection",
                                "description": "The application loads a Fragment based on a class name from an Intent, which can be controlled by a malicious app.",
                                "file": os.path.relpath(fpath, path),
                                "line": content.count('\n', 0, match.start()) + 1,
                                "poc": f"Fragment injection: `{match.group(0)}`",
                                "mitigation": "Validate the class name before loading the Fragment. Use a whitelist of allowed Fragments.",
                                "impact": "A malicious app could load a hidden or debug Fragment, leading to information disclosure or other vulnerabilities."
                            })
                except Exception:
                    continue
    return found

def check_tapjacking(path):
    found = []
    manifest_path = os.path.join(path, 'AndroidManifest.xml')
    if not os.path.exists(manifest_path):
        return found
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        ns = {'android': 'http://schemas.android.com/apk/res/android'}
        app_tag = root.find('application')
        if app_tag is None:
            return found
        for activity in app_tag.findall('activity'):
            name = activity.attrib.get(f"{{{ns['android']}}}name", 'Unknown')
            filter_touches = activity.attrib.get(f"{{{ns['android']}}}filterTouchesWhenObscured")
            if filter_touches != 'true':
                found.append({
                    "severity": "Medium",
                    "title": "Tapjacking Vulnerability",
                    "description": f"The activity '{name}' does not have the `filterTouchesWhenObscured` attribute set to `true`, making it vulnerable to tapjacking.",
                    "file": "AndroidManifest.xml",
                    "poc": f"Activity: `{name}` is missing `android:filterTouchesWhenObscured=\"true\"`.",
                    "mitigation": "Set `android:filterTouchesWhenObscured=\"true\"` for all sensitive activities.",
                    "impact": "A malicious application can overlay the vulnerable app and trick the user into performing unintended actions."
                })
    except ET.ParseError:
        pass
    return found

def check_missing_protection_level(path):
    found = []
    manifest_path = os.path.join(path, 'AndroidManifest.xml')
    if not os.path.exists(manifest_path):
        return found
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        ns = {'android': 'http://schemas.android.com/apk/res/android'}
        for permission in root.findall('permission'):
            name = permission.attrib.get(f"{{{ns['android']}}}name", 'Unknown')
            protection_level = permission.attrib.get(f"{{{ns['android']}}}protectionLevel")
            if not protection_level:
                found.append({
                    "severity": "Medium",
                    "title": "Missing Protection Level for Custom Permission",
                    "description": f"The custom permission '{name}' does not have a `protectionLevel` attribute defined.",
                    "file": "AndroidManifest.xml",
                    "poc": f"Permission: `{name}` is missing the `android:protectionLevel` attribute.",
                    "mitigation": "Define a `protectionLevel` for all custom permissions. The recommended level is `signature`.",
                    "impact": "Any application can request and be granted this permission, potentially leading to unauthorized access to protected components."
                })
    except ET.ParseError:
        pass
    return found
