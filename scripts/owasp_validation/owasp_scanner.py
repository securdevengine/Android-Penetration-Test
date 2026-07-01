#!/usr/bin/env python3

import os
import sys
import re
import json
import argparse
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
import zipfile
import sqlite3
import tempfile
from datetime import datetime

class OWASPMobileScanner:
    def __init__(self, apk_path, output_dir=None):
        self.apk_path = Path(apk_path)
        self.output_dir = Path(output_dir) if output_dir else Path(f"output/owasp_scan_{self.apk_path.stem}")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Results storage
        self.findings = {
            'M1_Credential_Usage': [],
            'M2_Supply_Chain': [],
            'M3_Authentication': [],
            'M4_Input_Validation': [],
            'M5_Communication': [],
            'M6_Privacy_Controls': [],
            'M7_Binary_Protections': [],
            'M8_Security_Config': [],
            'M9_Data_Storage': [],
            'M10_Cryptography': []
        }
        
        # Decompiled paths
        self.jadx_output = self.output_dir / "jadx"
        self.apktool_output = self.output_dir / "apktool"
        
    def run_command(self, cmd, capture_output=True, timeout=300):
        try:
            if isinstance(cmd, str):
                cmd = cmd.split()
            result = subprocess.run(cmd, capture_output=capture_output, 
                                  text=True, timeout=timeout, cwd=self.output_dir)
            return result.returncode == 0, result.stdout, result.stderr
        except Exception as e:
            return False, "", str(e)
    
    def decompile_apk(self):
        print("[*] Decompiling APK...")
        
        # JADX decompilation
        jadx_cmd = f"jadx -d {self.jadx_output} {self.apk_path}"
        success, stdout, stderr = self.run_command(jadx_cmd)
        if not success:
            print(f"[!] JADX decompilation failed: {stderr}")
        
        # APKTool decompilation
        apktool_cmd = f"apktool d {self.apk_path} -o {self.apktool_output}"
        success, stdout, stderr = self.run_command(apktool_cmd)
        if not success:
            print(f"[!] APKTool decompilation failed: {stderr}")
        
        print("[+] APK decompiled successfully")
    
    def scan_m1_credential_usage(self):
        print("[*] Scanning M1: Improper Credential Usage...")
        
        findings = []
        
        # Search for hardcoded credentials in Java files
        if self.jadx_output.exists():
            for java_file in self.jadx_output.rglob("*.java"):
                try:
                    content = java_file.read_text(errors='ignore')
                    
                    # Credential patterns
                    patterns = [
                        (r'(?i)(password|pwd|pass)\s*=\s*["\'][^"\']{3,}["\']', 'Hardcoded Password'),
                        (r'(?i)(api[_-]?key|apikey)\s*=\s*["\'][^"\']{10,}["\']', 'Hardcoded API Key'),
                        (r'(?i)(secret[_-]?key|secretkey)\s*=\s*["\'][^"\']{10,}["\']', 'Hardcoded Secret Key'),
                        (r'(?i)(token|auth[_-]?token)\s*=\s*["\'][^"\']{20,}["\']', 'Hardcoded Token'),
                        (r'(?i)(private[_-]?key|privatekey)\s*=\s*["\'][^"\']{50,}["\']', 'Hardcoded Private Key'),
                        (r'(?i)jdbc:[^"\']*password=[^"\'&]*', 'Database Connection String'),
                        (r'(?i)Bearer\s+[A-Za-z0-9+/=]{20,}', 'Hardcoded Bearer Token')
                    ]
                    
                    for pattern, description in patterns:
                        matches = re.finditer(pattern, content)
                        for match in matches:
                            line_num = content[:match.start()].count('\n') + 1
                            findings.append({
                                'type': description,
                                'file': str(java_file.relative_to(self.jadx_output)),
                                'line': line_num,
                                'code': match.group(0)[:100] + "..." if len(match.group(0)) > 100 else match.group(0),
                                'severity': 'HIGH'
                            })
                            
                except Exception as e:
                    continue
        
        # Search in XML resources
        if self.apktool_output.exists():
            for xml_file in self.apktool_output.rglob("*.xml"):
                try:
                    content = xml_file.read_text(errors='ignore')
                    
                    # XML credential patterns
                    xml_patterns = [
                        (r'(?i)<string[^>]*name="[^"]*(?:password|secret|key|token)[^"]*"[^>]*>[^<]{3,}</string>', 'Credential in String Resource'),
                        (r'(?i)android:password="[^"]{3,}"', 'Password in XML Attribute')
                    ]
                    
                    for pattern, description in xml_patterns:
                        matches = re.finditer(pattern, content)
                        for match in matches:
                            line_num = content[:match.start()].count('\n') + 1
                            findings.append({
                                'type': description,
                                'file': str(xml_file.relative_to(self.apktool_output)),
                                'line': line_num,
                                'code': match.group(0),
                                'severity': 'MEDIUM'
                            })
                            
                except Exception as e:
                    continue
        
        self.findings['M1_Credential_Usage'] = findings
        print(f"[+] M1 scan complete: {len(findings)} findings")
    
    def scan_m2_supply_chain(self):
        print("[*] Scanning M2: Inadequate Supply Chain Security...")
        
        findings = []
        
        if self.jadx_output.exists():
            # Find third-party libraries
            third_party_packages = set()
            
            for java_file in self.jadx_output.rglob("*.java"):
                try:
                    content = java_file.read_text(errors='ignore')
                    
                    # Extract import statements
                    imports = re.findall(r'import\s+([\w.]+)', content)
                    for imp in imports:
                        if any(imp.startswith(prefix) for prefix in ['com.google', 'com.facebook', 'com.amazon', 'org.apache', 'com.squareup']):
                            third_party_packages.add(imp.split('.')[0] + '.' + imp.split('.')[1] + '.' + imp.split('.')[2])
                
                except Exception as e:
                    continue
            
            # Known vulnerable libraries (simplified list)
            known_vulnerable = {
                'com.google.firebase': 'Firebase SDK - Check for latest version',
                'com.facebook.android': 'Facebook SDK - Potential privacy issues',
                'org.apache.http': 'Apache HTTP Client - Deprecated, use OkHttp',
                'com.squareup.okhttp': 'OkHttp - Check for latest version'
            }
            
            for package in third_party_packages:
                if package in known_vulnerable:
                    findings.append({
                        'type': 'Third-party Library',
                        'package': package,
                        'issue': known_vulnerable[package],
                        'severity': 'MEDIUM'
                    })
        
        self.findings['M2_Supply_Chain'] = findings
        print(f"[+] M2 scan complete: {len(findings)} findings")
    
    def scan_m3_authentication(self):
        print("[*] Scanning M3: Insecure Authentication/Authorization...")
        
        findings = []
        
        if self.jadx_output.exists():
            for java_file in self.jadx_output.rglob("*.java"):
                try:
                    content = java_file.read_text(errors='ignore')
                    
                    # Authentication vulnerability patterns
                    patterns = [
                        (r'(?i)jwt.*alg.*none', 'JWT with alg=none vulnerability'),
                        (r'(?i)password\.equals\([^)]*\)', 'Weak password comparison'),
                        (r'(?i)session.*timeout.*0|setTimeout.*0', 'No session timeout'),
                        (r'(?i)authenticate.*return\s+true', 'Always returns true authentication'),
                        (r'(?i)biometric.*bypass|fingerprint.*bypass', 'Biometric bypass detected')
                    ]
                    
                    for pattern, description in patterns:
                        matches = re.finditer(pattern, content)
                        for match in matches:
                            line_num = content[:match.start()].count('\n') + 1
                            findings.append({
                                'type': description,
                                'file': str(java_file.relative_to(self.jadx_output)),
                                'line': line_num,
                                'code': match.group(0),
                                'severity': 'HIGH'
                            })
                            
                except Exception as e:
                    continue
        
        self.findings['M3_Authentication'] = findings
        print(f"[+] M3 scan complete: {len(findings)} findings")
    
    def scan_m4_input_validation(self):
        print("[*] Scanning M4: Insufficient Input/Output Validation...")
        
        findings = []
        
        if self.jadx_output.exists():
            for java_file in self.jadx_output.rglob("*.java"):
                try:
                    content = java_file.read_text(errors='ignore')
                    
                    # Input validation vulnerability patterns
                    patterns = [
                        (r'(?i)execSQL.*\+|rawQuery.*\+', 'SQL Injection vulnerability'),
                        (r'(?i)webview.*loadUrl.*\+', 'WebView URL injection'),
                        (r'(?i)addJavascriptInterface', 'JavaScript interface - potential XSS'),
                        (r'(?i)getStringExtra.*without.*validation', 'Intent parameter without validation'),
                        (r'(?i)file.*getPath.*\.\./', 'Path traversal vulnerability')
                    ]
                    
                    for pattern, description in patterns:
                        matches = re.finditer(pattern, content)
                        for match in matches:
                            line_num = content[:match.start()].count('\n') + 1
                            findings.append({
                                'type': description,
                                'file': str(java_file.relative_to(self.jadx_output)),
                                'line': line_num,
                                'code': match.group(0),
                                'severity': 'HIGH'
                            })
                            
                except Exception as e:
                    continue
        
        self.findings['M4_Input_Validation'] = findings
        print(f"[+] M4 scan complete: {len(findings)} findings")
    
    def scan_m5_communication(self):
        print("[*] Scanning M5: Insecure Communication...")
        
        findings = []
        
        # Check AndroidManifest.xml for cleartext traffic
        manifest_path = self.apktool_output / "AndroidManifest.xml"
        if manifest_path.exists():
            try:
                tree = ET.parse(manifest_path)
                root = tree.getroot()
                
                # Check for cleartext traffic
                app_element = root.find('application')
                if app_element is not None:
                    cleartext = app_element.get('{http://schemas.android.com/apk/res/android}usesCleartextTraffic')
                    if cleartext == 'true':
                        findings.append({
                            'type': 'Cleartext Traffic Allowed',
                            'file': 'AndroidManifest.xml',
                            'severity': 'HIGH',
                            'description': 'Application allows cleartext HTTP traffic'
                        })
                
            except Exception as e:
                print(f"[!] Error parsing AndroidManifest.xml: {e}")
        
        # Check for insecure HTTP usage in code
        if self.jadx_output.exists():
            for java_file in self.jadx_output.rglob("*.java"):
                try:
                    content = java_file.read_text(errors='ignore')
                    
                    # Communication security patterns
                    patterns = [
                        (r'http://[^"\s]+', 'HTTP URL usage'),
                        (r'(?i)TrustAllTrustManager|ALLOW_ALL_HOSTNAME_VERIFIER', 'Trust all certificates'),
                        (r'(?i)SSLv3|TLS.*1\.0|TLS.*1\.1', 'Weak SSL/TLS version'),
                        (r'(?i)trustStore.*null|hostnameVerifier.*null', 'Disabled certificate validation')
                    ]
                    
                    for pattern, description in patterns:
                        matches = re.finditer(pattern, content)
                        for match in matches:
                            line_num = content[:match.start()].count('\n') + 1
                            findings.append({
                                'type': description,
                                'file': str(java_file.relative_to(self.jadx_output)),
                                'line': line_num,
                                'code': match.group(0),
                                'severity': 'HIGH' if 'HTTP URL' in description else 'MEDIUM'
                            })
                            
                except Exception as e:
                    continue
        
        self.findings['M5_Communication'] = findings
        print(f"[+] M5 scan complete: {len(findings)} findings")
    
    def scan_m6_privacy_controls(self):
        print("[*] Scanning M6: Inadequate Privacy Controls...")
        
        findings = []
        
        # Check permissions in AndroidManifest.xml
        manifest_path = self.apktool_output / "AndroidManifest.xml"
        if manifest_path.exists():
            try:
                tree = ET.parse(manifest_path)
                root = tree.getroot()
                
                # Dangerous permissions
                dangerous_permissions = [
                    'android.permission.CAMERA',
                    'android.permission.RECORD_AUDIO',
                    'android.permission.ACCESS_FINE_LOCATION',
                    'android.permission.ACCESS_COARSE_LOCATION',
                    'android.permission.READ_CONTACTS',
                    'android.permission.READ_SMS',
                    'android.permission.READ_PHONE_STATE'
                ]
                
                for permission_elem in root.findall('uses-permission'):
                    perm_name = permission_elem.get('{http://schemas.android.com/apk/res/android}name')
                    if perm_name in dangerous_permissions:
                        findings.append({
                            'type': 'Dangerous Permission',
                            'permission': perm_name,
                            'file': 'AndroidManifest.xml',
                            'severity': 'MEDIUM',
                            'description': f'App requests sensitive permission: {perm_name}'
                        })
                
            except Exception as e:
                print(f"[!] Error parsing AndroidManifest.xml: {e}")
        
        # Check for analytics and tracking
        if self.jadx_output.exists():
            for java_file in self.jadx_output.rglob("*.java"):
                try:
                    content = java_file.read_text(errors='ignore')
                    
                    # Privacy-related patterns
                    patterns = [
                        (r'(?i)analytics|tracking|firebase|facebook.*track', 'Analytics/Tracking detected'),
                        (r'(?i)location.*send|gps.*transmit', 'Location data transmission'),
                        (r'(?i)contact.*upload|phonebook.*sync', 'Contact data handling')
                    ]
                    
                    for pattern, description in patterns:
                        matches = re.finditer(pattern, content)
                        for match in matches:
                            line_num = content[:match.start()].count('\n') + 1
                            findings.append({
                                'type': description,
                                'file': str(java_file.relative_to(self.jadx_output)),
                                'line': line_num,
                                'code': match.group(0)[:50] + "...",
                                'severity': 'MEDIUM'
                            })
                            
                except Exception as e:
                    continue
        
        self.findings['M6_Privacy_Controls'] = findings
        print(f"[+] M6 scan complete: {len(findings)} findings")
    
    def scan_m7_binary_protections(self):
        print("[*] Scanning M7: Insufficient Binary Protections...")
        
        findings = []
        
        # Check for obfuscation
        if self.jadx_output.exists():
            total_classes = 0
            obfuscated_classes = 0
            
            for java_file in self.jadx_output.rglob("*.java"):
                total_classes += 1
                filename = java_file.stem
                
                # Check for obfuscated class names (single letters, short names)
                if len(filename) <= 2 or re.match(r'^[a-z]$', filename):
                    obfuscated_classes += 1
            
            if total_classes > 0:
                obfuscation_ratio = obfuscated_classes / total_classes
                if obfuscation_ratio < 0.3:  # Less than 30% obfuscated
                    findings.append({
                        'type': 'Insufficient Code Obfuscation',
                        'description': f'Only {obfuscation_ratio:.1%} of classes appear obfuscated',
                        'severity': 'MEDIUM'
                    })
        
        # Check for anti-debugging
        if self.jadx_output.exists():
            anti_debug_found = False
            
            for java_file in self.jadx_output.rglob("*.java"):
                try:
                    content = java_file.read_text(errors='ignore')
                    
                    # Anti-debugging patterns
                    anti_debug_patterns = [
                        r'(?i)isDebuggerConnected',
                        r'(?i)debug.*detect',
                        r'(?i)root.*detect',
                        r'(?i)emulator.*detect'
                    ]
                    
                    for pattern in anti_debug_patterns:
                        if re.search(pattern, content):
                            anti_debug_found = True
                            break
                    
                    if anti_debug_found:
                        break
                        
                except Exception as e:
                    continue
            
            if not anti_debug_found:
                findings.append({
                    'type': 'Missing Anti-Debugging Protection',
                    'description': 'No anti-debugging mechanisms detected',
                    'severity': 'LOW'
                })
        
        # Check debuggable flag
        manifest_path = self.apktool_output / "AndroidManifest.xml"
        if manifest_path.exists():
            try:
                tree = ET.parse(manifest_path)
                root = tree.getroot()
                
                app_element = root.find('application')
                if app_element is not None:
                    debuggable = app_element.get('{http://schemas.android.com/apk/res/android}debuggable')
                    if debuggable == 'true':
                        findings.append({
                            'type': 'Debug Mode Enabled',
                            'file': 'AndroidManifest.xml',
                            'severity': 'HIGH',
                            'description': 'Application has debug mode enabled'
                        })
                
            except Exception as e:
                print(f"[!] Error parsing AndroidManifest.xml: {e}")
        
        self.findings['M7_Binary_Protections'] = findings
        print(f"[+] M7 scan complete: {len(findings)} findings")
    
    def scan_m8_security_config(self):
        print("[*] Scanning M8: Security Misconfiguration...")
        
        findings = []
        
        # Check AndroidManifest.xml for misconfigurations
        manifest_path = self.apktool_output / "AndroidManifest.xml"
        if manifest_path.exists():
            try:
                tree = ET.parse(manifest_path)
                root = tree.getroot()
                
                # Check for exported components
                for component_type in ['activity', 'service', 'receiver', 'provider']:
                    for component in root.findall(component_type):
                        exported = component.get('{http://schemas.android.com/apk/res/android}exported')
                        name = component.get('{http://schemas.android.com/apk/res/android}name')
                        
                        if exported == 'true':
                            findings.append({
                                'type': f'Exported {component_type.title()}',
                                'component': name,
                                'file': 'AndroidManifest.xml',
                                'severity': 'MEDIUM',
                                'description': f'{component_type.title()} is exported and accessible to other apps'
                            })
                
                # Check backup flag
                app_element = root.find('application')
                if app_element is not None:
                    backup = app_element.get('{http://schemas.android.com/apk/res/android}allowBackup')
                    if backup == 'true':
                        findings.append({
                            'type': 'Backup Allowed',
                            'file': 'AndroidManifest.xml',
                            'severity': 'MEDIUM',
                            'description': 'Application allows backup of data'
                        })
                
            except Exception as e:
                print(f"[!] Error parsing AndroidManifest.xml: {e}")
        
        self.findings['M8_Security_Config'] = findings
        print(f"[+] M8 scan complete: {len(findings)} findings")
    
    def scan_m9_data_storage(self):
        print("[*] Scanning M9: Insecure Data Storage...")
        
        findings = []
        
        if self.jadx_output.exists():
            for java_file in self.jadx_output.rglob("*.java"):
                try:
                    content = java_file.read_text(errors='ignore')
                    
                    # Data storage vulnerability patterns
                    patterns = [
                        (r'(?i)MODE_WORLD_READABLE|MODE_WORLD_WRITABLE', 'World readable/writable file mode'),
                        (r'(?i)sharedPreferences.*putString.*password', 'Password in SharedPreferences'),
                        (r'(?i)getExternalStorageDirectory', 'External storage usage'),
                        (r'(?i)openFileOutput.*MODE_WORLD', 'World accessible file output'),
                        (r'(?i)sqlite.*password.*null', 'Unencrypted SQLite database')
                    ]
                    
                    for pattern, description in patterns:
                        matches = re.finditer(pattern, content)
                        for match in matches:
                            line_num = content[:match.start()].count('\n') + 1
                            findings.append({
                                'type': description,
                                'file': str(java_file.relative_to(self.jadx_output)),
                                'line': line_num,
                                'code': match.group(0),
                                'severity': 'HIGH'
                            })
                            
                except Exception as e:
                    continue
        
        self.findings['M9_Data_Storage'] = findings
        print(f"[+] M9 scan complete: {len(findings)} findings")
    
    def scan_m10_cryptography(self):
        print("[*] Scanning M10: Insufficient Cryptography...")
        
        findings = []
        
        if self.jadx_output.exists():
            for java_file in self.jadx_output.rglob("*.java"):
                try:
                    content = java_file.read_text(errors='ignore')
                    
                    # Cryptography vulnerability patterns
                    patterns = [
                        (r'(?i)DES|3DES|RC4', 'Weak encryption algorithm'),
                        (r'(?i)MD5|SHA1(?![0-9])', 'Weak hash algorithm'),
                        (r'(?i)ECB', 'Weak cipher mode (ECB)'),
                        (r'(?i)Random\(\)|Math\.random', 'Weak random number generation'),
                        (r'(?i)hardcoded.*key|static.*key.*=', 'Hardcoded encryption key'),
                        (r'(?i)AES.*128', 'Weak key size (AES-128)')
                    ]
                    
                    for pattern, description in patterns:
                        matches = re.finditer(pattern, content)
                        for match in matches:
                            line_num = content[:match.start()].count('\n') + 1
                            severity = 'HIGH' if 'Weak' in description else 'MEDIUM'
                            findings.append({
                                'type': description,
                                'file': str(java_file.relative_to(self.jadx_output)),
                                'line': line_num,
                                'code': match.group(0),
                                'severity': severity
                            })
                            
                except Exception as e:
                    continue
        
        self.findings['M10_Cryptography'] = findings
        print(f"[+] M10 scan complete: {len(findings)} findings")
    
    def generate_report(self):
        print("[*] Generating OWASP Mobile Top 10 report...")
        
        # Calculate summary
        total_findings = sum(len(findings) for findings in self.findings.values())
        high_severity = sum(len([f for f in findings if f.get('severity') == 'HIGH']) 
                           for findings in self.findings.values())
        medium_severity = sum(len([f for f in findings if f.get('severity') == 'MEDIUM']) 
                             for findings in self.findings.values())
        low_severity = sum(len([f for f in findings if f.get('severity') == 'LOW']) 
                          for findings in self.findings.values())
        
        # Generate JSON report
        report = {
            'scan_info': {
                'apk_path': str(self.apk_path),
                'scan_date': datetime.now().isoformat(),
                'total_findings': total_findings,
                'severity_breakdown': {
                    'HIGH': high_severity,
                    'MEDIUM': medium_severity,
                    'LOW': low_severity
                }
            },
            'findings': self.findings
        }
        
        json_report_path = self.output_dir / "owasp_mobile_top10_report.json"
        with open(json_report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Generate HTML report
        html_report = self.generate_html_report(report)
        html_report_path = self.output_dir / "owasp_mobile_top10_report.html"
        with open(html_report_path, 'w') as f:
            f.write(html_report)
        
        print(f"[+] Reports generated:")
        print(f"    JSON: {json_report_path}")
        print(f"    HTML: {html_report_path}")
        
        # Print summary
        print(f"\n[+] OWASP Mobile Top 10 Scan Summary:")
        print(f"    Total Findings: {total_findings}")
        print(f"    High Severity: {high_severity}")
        print(f"    Medium Severity: {medium_severity}")
        print(f"    Low Severity: {low_severity}")
        
        return report
    
    def generate_html_report(self, report):
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>OWASP Mobile Top 10 2024 Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
                .summary {{ background: #ecf0f1; padding: 15px; margin: 20px 0; border-radius: 5px; }}
                .finding {{ margin: 10px 0; padding: 10px; border-left: 4px solid #3498db; background: #f8f9fa; }}
                .high {{ border-left-color: #e74c3c; }}
                .medium {{ border-left-color: #f39c12; }}
                .low {{ border-left-color: #27ae60; }}
                .category {{ margin: 30px 0; }}
                .category h2 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
                code {{ background: #f1c40f; padding: 2px 4px; border-radius: 3px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>OWASP Mobile Top 10 2024 Security Assessment</h1>
                <p>APK: {report['scan_info']['apk_path']}</p>
                <p>Scan Date: {report['scan_info']['scan_date']}</p>
            </div>
            
            <div class="summary">
                <h2>Executive Summary</h2>
                <p><strong>Total Findings:</strong> {report['scan_info']['total_findings']}</p>
                <p><strong>High Severity:</strong> {report['scan_info']['severity_breakdown']['HIGH']}</p>
                <p><strong>Medium Severity:</strong> {report['scan_info']['severity_breakdown']['MEDIUM']}</p>
                <p><strong>Low Severity:</strong> {report['scan_info']['severity_breakdown']['LOW']}</p>
            </div>
        """
        
        # Add findings for each category
        owasp_categories = {
            'M1_Credential_Usage': 'M1: Improper Credential Usage',
            'M2_Supply_Chain': 'M2: Inadequate Supply Chain Security',
            'M3_Authentication': 'M3: Insecure Authentication/Authorization',
            'M4_Input_Validation': 'M4: Insufficient Input/Output Validation',
            'M5_Communication': 'M5: Insecure Communication',
            'M6_Privacy_Controls': 'M6: Inadequate Privacy Controls',
            'M7_Binary_Protections': 'M7: Insufficient Binary Protections',
            'M8_Security_Config': 'M8: Security Misconfiguration',
            'M9_Data_Storage': 'M9: Insecure Data Storage',
            'M10_Cryptography': 'M10: Insufficient Cryptography'
        }
        
        for category_key, category_name in owasp_categories.items():
            findings = report['findings'].get(category_key, [])
            html += f"""
            <div class="category">
                <h2>{category_name}</h2>
                <p><strong>Findings:</strong> {len(findings)}</p>
            """
            
            if findings:
                for finding in findings:
                    severity_class = finding.get('severity', 'MEDIUM').lower()
                    html += f"""
                    <div class="finding {severity_class}">
                        <h4>{finding.get('type', 'Unknown')}</h4>
                        <p><strong>Severity:</strong> {finding.get('severity', 'MEDIUM')}</p>
                        <p><strong>File:</strong> {finding.get('file', 'N/A')}</p>
                        {f"<p><strong>Line:</strong> {finding.get('line', 'N/A')}</p>" if 'line' in finding else ''}
                        {f"<p><strong>Description:</strong> {finding.get('description', 'N/A')}</p>" if 'description' in finding else ''}
                        {f"<p><strong>Code:</strong> <code>{finding.get('code', 'N/A')}</code></p>" if 'code' in finding else ''}
                    </div>
                    """
            else:
                html += "<p>No findings detected for this category.</p>"
            
            html += "</div>"
        
        html += """
        </body>
        </html>
        """
        
        return html
    
    def run_full_scan(self):
        print("OWASP Mobile Top 10 2024 Scanner")
        print("=" * 50)
        
        # Decompile APK
        self.decompile_apk()
        
        # Run all scans
        self.scan_m1_credential_usage()
        self.scan_m2_supply_chain()
        self.scan_m3_authentication()
        self.scan_m4_input_validation()
        self.scan_m5_communication()
        self.scan_m6_privacy_controls()
        self.scan_m7_binary_protections()
        self.scan_m8_security_config()
        self.scan_m9_data_storage()
        self.scan_m10_cryptography()
        
        # Generate report
        return self.generate_report()

def main():
    parser = argparse.ArgumentParser(
        description='OWASP Mobile Top 10 (2024) validation scanner for Android APKs'
    )
    parser.add_argument('apk_path', help='Path to the APK file to scan')
    parser.add_argument('-o', '--output', help='Output directory for scan results')
    args = parser.parse_args()

    if not os.path.exists(args.apk_path):
        print(f"Error: APK file not found: {args.apk_path}")
        sys.exit(1)

    scanner = OWASPMobileScanner(args.apk_path, output_dir=args.output)
    scanner.run_full_scan()

    print(f"\nScan complete! Check the output directory: {scanner.output_dir}")

if __name__ == "__main__":
    main()