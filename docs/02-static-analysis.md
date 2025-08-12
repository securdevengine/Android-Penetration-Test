# 🔍 Static Analysis Guide

This guide covers comprehensive static analysis techniques for Android applications, from basic APK decompilation to advanced vulnerability discovery.

## 🎯 Objectives

- Decompile APK files using multiple tools and techniques
- Extract hidden API endpoints and secrets
- Analyze AndroidManifest.xml for security misconfigurations
- Examine native libraries for vulnerabilities
- Automate static analysis with custom scripts

## 🛠️ Tools Overview

### Primary Decompilers
- **JADX** - Java/Kotlin decompilation with GUI support
- **APKTool** - Resource extraction and Smali analysis
- **Ghidra** - Native library reverse engineering
- **MobSF** - Automated vulnerability scanning

### Supporting Tools
- **Bytecode Viewer** - Multi-engine decompilation
- **Androguard** - Python-based APK analysis
- **dex2jar** - DEX to JAR conversion
- **JD-GUI** - JAR file examination

## 🚀 Step-by-Step Analysis Process

### Phase 1: Initial APK Inspection

#### 1.1 Basic APK Information
```bash
# Get APK metadata
aapt dump badging target.apk

# Extract basic info
unzip -l target.apk | head -20

# Check file size and structure
du -sh target.apk
file target.apk
```

#### 1.2 Certificate Analysis
```bash
# Extract certificate information
keytool -printcert -jarfile target.apk

# Check signature version
apksigner verify --verbose target.apk

# Analyze signing certificate
openssl pkcs7 -inform DER -in META-INF/CERT.RSA -noout -print_certs -text
```

### Phase 2: Decompilation

#### 2.1 JADX Decompilation (Recommended)
```bash
# Basic decompilation
jadx target.apk -d output/jadx_decompiled

# Advanced decompilation with obfuscation handling
jadx --deobf --show-bad-code --escape-unicode target.apk -d output/jadx_advanced

# GUI mode for interactive analysis
jadx-gui target.apk
```

**JADX Command Options:**
- `--deobf` - Attempt deobfuscation
- `--show-bad-code` - Show problematic code sections
- `--escape-unicode` - Escape unicode characters
- `--respect-bytecode-offset` - Keep original line numbers

#### 2.2 APKTool Extraction
```bash
# Extract all resources and Smali code
apktool d target.apk -o output/apktool_extracted

# Force manifest decoding
apktool d --force-manifest target.apk -o output/manifest_forced

# Extract only resources
apktool d --only-main-classes target.apk -o output/resources_only
```

#### 2.3 Alternative Decompilation Methods
```bash
# Method 1: dex2jar + JD-GUI
d2j-dex2jar target.apk -o target.jar
# Open target.jar in JD-GUI

# Method 2: Bytecode Viewer
# GUI tool - Load APK directly

# Method 3: Androguard
python -c "
import androguard
from androguard.misc import AnalyzeAPK
a, d, dx = AnalyzeAPK('target.apk')
print('Package:', a.get_package())
print('Activities:', a.get_activities())
"
```

### Phase 3: API Endpoint Discovery

#### 3.1 Automated Endpoint Extraction
```bash
# Use custom endpoint extractor
python scripts/static_analysis/endpoint_extractor.py target.apk

# Grep-based search
grep -rE "(https?://|www\.)[^\"]+" output/jadx_decompiled/

# Advanced regex patterns
grep -rE "(['\"])(https?://[^'\"]+)" output/jadx_decompiled/ | sort -u
```

#### 3.2 Network Library Analysis

**Retrofit Detection:**
```bash
# Search for Retrofit annotations
grep -r "@GET\|@POST\|@PUT\|@DELETE" output/jadx_decompiled/

# Find base URLs
grep -r "baseUrl\|BASE_URL\|Retrofit\.Builder" output/jadx_decompiled/
```

**OkHttp Detection:**
```bash
# Find OkHttp usage
grep -r "OkHttpClient\|Request\.Builder" output/jadx_decompiled/

# Locate interceptors
grep -r "Interceptor\|addInterceptor" output/jadx_decompiled/
```

**Volley Detection:**
```bash
# Search for Volley requests
grep -r "StringRequest\|JsonObjectRequest\|RequestQueue" output/jadx_decompiled/
```

#### 3.3 WebView URL Discovery
```bash
# Find WebView URLs
grep -r "loadUrl\|evaluateJavascript\|addJavascriptInterface" output/jadx_decompiled/

# Check for JavaScript bridges
grep -r "@JavascriptInterface" output/jadx_decompiled/
```

### Phase 4: Secret and Credential Discovery

#### 4.1 Comprehensive Secret Search
```bash
# Use custom secret finder
python scripts/static_analysis/secret_finder.py output/jadx_decompiled/

# Manual regex searches
grep -rE "(api[_-]?key|secret|token|password|auth[_-]?key)" output/jadx_decompiled/ -i

# Database credentials
grep -rE "(database|db_|mysql|postgres|mongodb)" output/jadx_decompiled/ -i

# Cloud service keys
grep -rE "(aws_|azure_|gcp_|firebase)" output/jadx_decompiled/ -i
```

#### 4.2 Hardcoded Credentials Pattern Search
```python
# Custom Python script for advanced secret detection
import re
import os

secret_patterns = {
    'api_key': r'["\']api[_-]?key["\'][\s]*[:=][\s]*["\']([^"\']+)["\']',
    'jwt_secret': r'["\']jwt[_-]?secret["\'][\s]*[:=][\s]*["\']([^"\']+)["\']',
    'database_url': r'["\']database[_-]?url["\'][\s]*[:=][\s]*["\']([^"\']+)["\']',
    'aws_key': r'["\']aws[_-]?access[_-]?key["\'][\s]*[:=][\s]*["\']([^"\']+)["\']',
    'private_key': r'-----BEGIN[\s\w]*PRIVATE KEY-----'
}

def find_secrets(directory):
    results = {}
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(('.java', '.kt', '.xml', '.json')):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for secret_type, pattern in secret_patterns.items():
                            matches = re.findall(pattern, content, re.IGNORECASE)
                            if matches:
                                if secret_type not in results:
                                    results[secret_type] = []
                                results[secret_type].extend([(file_path, match) for match in matches])
                except Exception as e:
                    continue
    return results
```

### Phase 5: AndroidManifest Analysis

#### 5.1 Critical Security Checks
```bash
# Use custom manifest analyzer
python scripts/static_analysis/manifest_analyzer.py output/apktool_extracted/AndroidManifest.xml

# Manual analysis
cat output/apktool_extracted/AndroidManifest.xml | xmllint --format -
```

#### 5.2 Key Security Findings

**Cleartext Traffic:**
```xml
<!-- Vulnerable configuration -->
<application android:usesCleartextTraffic="true">

<!-- Check network security config -->
<meta-data 
    android:name="android.security.net.config" 
    android:resource="@xml/network_security_config"/>
```

**Exported Components:**
```bash
# Find exported activities
grep -A5 -B5 'android:exported="true"' output/apktool_extracted/AndroidManifest.xml

# Check for intent filters without protection
grep -A10 'intent-filter' output/apktool_extracted/AndroidManifest.xml
```

**Dangerous Permissions:**
```bash
# Extract all permissions
grep 'uses-permission' output/apktool_extracted/AndroidManifest.xml

# Flag dangerous permissions
grep -E "(READ_SMS|WRITE_SMS|READ_CONTACTS|CAMERA|RECORD_AUDIO)" output/apktool_extracted/AndroidManifest.xml
```

**Backup Settings:**
```xml
<!-- Check backup configuration -->
<application android:allowBackup="true">
<application android:debuggable="true">
```

### Phase 6: Native Library Analysis

#### 6.1 Extract Native Libraries
```bash
# Extract .so files
unzip target.apk "lib/*.so" -d output/native_libs

# List all native libraries
find output/native_libs -name "*.so" -exec file {} \;
```

#### 6.2 Ghidra Analysis
```bash
# Automated Ghidra analysis script
python scripts/static_analysis/ghidra_analyzer.py output/native_libs/

# Manual Ghidra analysis steps:
# 1. Create new project
# 2. Import .so file
# 3. Analyze with default options
# 4. Search for JNI functions
# 5. Examine strings and cryptographic functions
```

#### 6.3 Strings Analysis
```bash
# Extract strings from native libraries
for so_file in output/native_libs/lib/*/*.so; do
    echo "=== $so_file ==="
    strings "$so_file" | grep -E "(http|key|pass|secret|token)"
done
```

#### 6.4 JNI Function Discovery
```bash
# Find JNI function patterns
for so_file in output/native_libs/lib/*/*.so; do
    echo "=== $so_file ==="
    objdump -t "$so_file" | grep "Java_"
done
```

### Phase 7: Automated Vulnerability Scanning

#### 7.1 MobSF Static Analysis
```bash
# Run MobSF via API
curl -F "file=@target.apk" http://localhost:8000/api/v1/upload

# Or use GUI interface
# Navigate to http://localhost:8000
# Upload APK file
# Review generated report
```

#### 7.2 Custom Vulnerability Scanner
```python
# scripts/static_analysis/vuln_scanner.py
import json
import os
import re

class AndroidVulnerabilityScanner:
    def __init__(self, apk_path):
        self.apk_path = apk_path
        self.findings = []
    
    def scan_webview_vulnerabilities(self, decompiled_path):
        """Scan for WebView security issues"""
        webview_patterns = [
            r'setJavaScriptEnabled\(true\)',
            r'setAllowFileAccess\(true\)',
            r'setAllowUniversalAccessFromFileURLs\(true\)',
            r'addJavascriptInterface'
        ]
        
        for root, dirs, files in os.walk(decompiled_path):
            for file in files:
                if file.endswith('.java'):
                    file_path = os.path.join(root, file)
                    with open(file_path, 'r', errors='ignore') as f:
                        content = f.read()
                        for pattern in webview_patterns:
                            if re.search(pattern, content):
                                self.findings.append({
                                    'type': 'WebView Vulnerability',
                                    'file': file_path,
                                    'pattern': pattern,
                                    'severity': 'High'
                                })
    
    def scan_crypto_vulnerabilities(self, decompiled_path):
        """Scan for cryptographic vulnerabilities"""
        crypto_patterns = [
            r'DES|3DES',  # Weak encryption
            r'MD5|SHA1',  # Weak hashing
            r'ECB',       # Weak cipher mode
            r'Random\(\)',  # Weak randomness
        ]
        
        # Implementation similar to webview scan
        pass
    
    def generate_report(self):
        """Generate vulnerability report"""
        return {
            'scan_date': str(datetime.now()),
            'apk_path': self.apk_path,
            'total_findings': len(self.findings),
            'findings': self.findings
        }
```

### Phase 8: Advanced Analysis Techniques

#### 8.1 Control Flow Analysis
```python
# Using Androguard for CFG generation
from androguard.misc import AnalyzeAPK
from androguard.core.analysis import analysis

a, d, dx = AnalyzeAPK('target.apk')

# Get method analysis
for method in dx.get_methods():
    if method.is_external():
        continue
    
    # Generate control flow graph
    cfg = dx.get_method(method).get_cfg()
    
    # Analyze method calls
    xrefs = method.get_xref_to()
    print(f"Method: {method.name}")
    print(f"Called by: {len(xrefs)} methods")
```

#### 8.2 Data Flow Analysis
```python
# Track sensitive data flow
def trace_data_flow(dx, start_method, target_pattern):
    """Trace data flow from start method to targets matching pattern"""
    paths = []
    
    def dfs(current_method, path, visited):
        if current_method in visited:
            return
        
        visited.add(current_method)
        path.append(current_method)
        
        # Check if current method matches target
        if re.search(target_pattern, str(current_method)):
            paths.append(path.copy())
            return
        
        # Continue DFS to called methods
        for call in current_method.get_xref_to():
            dfs(call[1], path, visited.copy())
        
        path.pop()
    
    dfs(start_method, [], set())
    return paths
```

## 📊 Reporting and Documentation

### Generate Comprehensive Report
```python
# scripts/static_analysis/report_generator.py
class StaticAnalysisReport:
    def __init__(self, apk_path):
        self.apk_path = apk_path
        self.findings = {
            'api_endpoints': [],
            'secrets': [],
            'vulnerabilities': [],
            'manifest_issues': [],
            'native_lib_issues': []
        }
    
    def generate_html_report(self, output_file):
        """Generate HTML report with findings"""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Static Analysis Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .finding { margin: 20px 0; padding: 15px; border-left: 4px solid #007cba; }
                .high { border-left-color: #d32f2f; }
                .medium { border-left-color: #f57c00; }
                .low { border-left-color: #388e3c; }
            </style>
        </head>
        <body>
            <h1>Static Analysis Report</h1>
            <h2>APK: {apk_path}</h2>
            <!-- Report content -->
        </body>
        </html>
        """
        
        # Implement report generation logic
        pass
```

## 🔧 Automation Scripts

### Complete Static Analysis Automation
```bash
#!/bin/bash
# scripts/run_static_analysis.sh

APK_PATH=$1
OUTPUT_DIR="output/static_analysis/$(basename $APK_PATH .apk)"

echo "[+] Starting static analysis for $APK_PATH"

# Create output directory
mkdir -p $OUTPUT_DIR

# Step 1: Decompile with JADX
echo "[+] Decompiling with JADX..."
jadx --deobf --show-bad-code $APK_PATH -d $OUTPUT_DIR/jadx

# Step 2: Extract with APKTool
echo "[+] Extracting with APKTool..."
apktool d $APK_PATH -o $OUTPUT_DIR/apktool

# Step 3: Extract native libraries
echo "[+] Extracting native libraries..."
unzip $APK_PATH "lib/*.so" -d $OUTPUT_DIR/native_libs 2>/dev/null

# Step 4: Run automated analysis
echo "[+] Running endpoint extraction..."
python scripts/static_analysis/endpoint_extractor.py $APK_PATH > $OUTPUT_DIR/endpoints.txt

echo "[+] Running secret finder..."
python scripts/static_analysis/secret_finder.py $OUTPUT_DIR/jadx > $OUTPUT_DIR/secrets.txt

echo "[+] Analyzing manifest..."
python scripts/static_analysis/manifest_analyzer.py $OUTPUT_DIR/apktool/AndroidManifest.xml > $OUTPUT_DIR/manifest_analysis.txt

# Step 5: Generate report
echo "[+] Generating final report..."
python scripts/static_analysis/report_generator.py $OUTPUT_DIR

echo "[+] Static analysis complete. Results in $OUTPUT_DIR"
```

## 🎯 Best Practices

### 1. Systematic Approach
- Always start with basic APK info before decompilation
- Use multiple decompilers for comprehensive coverage
- Document all findings with evidence

### 2. Tool Selection
- **JADX** for readable Java/Kotlin code
- **APKTool** for XML resources and Smali
- **Ghidra** for native library analysis
- **MobSF** for automated vulnerability detection

### 3. Pattern Recognition
- Learn common obfuscation patterns
- Understand framework-specific implementations
- Recognize security anti-patterns

### 4. Verification
- Cross-reference findings across multiple tools
- Validate discovered endpoints with dynamic testing
- Confirm vulnerabilities with proof-of-concept exploits

## 🚀 Next Steps

1. ✅ Static Analysis Complete
2. 🔬 Continue to [Dynamic Analysis Guide](03-dynamic-analysis.md)
3. 🔐 Master [Authentication Analysis](04-authentication-analysis.md)
4. 🛡️ Study [Anti-Debugging Bypass](05-anti-debugging-bypass.md)

## 📚 References

- [JADX Documentation](https://github.com/skylot/jadx)
- [APKTool Documentation](https://ibotpeaches.github.io/Apktool/)
- [Ghidra User Guide](https://ghidra-sre.org/CheatSheet.html)
- [Android Security Guidelines](https://developer.android.com/topic/security)
- [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/)
