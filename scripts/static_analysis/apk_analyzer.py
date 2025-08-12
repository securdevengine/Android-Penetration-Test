#!/usr/bin/env python3

import os
import sys
import json
import subprocess
import argparse
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import zipfile
import xml.etree.ElementTree as ET
from datetime import datetime

class APKAnalyzer:
    def __init__(self, apk_path: str, output_dir: str = None):
        self.apk_path = Path(apk_path)
        self.output_dir = Path(output_dir) if output_dir else Path(f"output/static_analysis/{self.apk_path.stem}")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Analysis results
        self.results = {
            'apk_info': {},
            'manifest_analysis': {},
            'security_findings': [],
            'api_endpoints': [],
            'secrets': [],
            'permissions': [],
            'components': {},
            'native_libraries': [],
            'resources': {},
            'certificates': []
        }
        
        # Tool paths (will be detected automatically)
        self.tools = {
            'jadx': self._find_tool('jadx'),
            'apktool': self._find_tool('apktool'),
            'aapt': self._find_tool('aapt'),
            'keytool': self._find_tool('keytool')
        }
    
    def _find_tool(self, tool_name: str) -> Optional[str]:
        """Find tool in PATH or tools directory"""
        # Check in PATH
        tool_path = shutil.which(tool_name)
        if tool_path:
            return tool_path
        
        # Check in tools directory
        tools_dir = Path(__file__).parent.parent.parent / "tools"
        possible_paths = [
            tools_dir / tool_name / "bin" / tool_name,
            tools_dir / tool_name / tool_name,
            tools_dir / f"{tool_name}.jar"
        ]
        
        for path in possible_paths:
            if path.exists():
                return str(path)
        
        return None
    
    def analyze(self) -> Dict:
        """Perform comprehensive APK analysis"""
        print(f"[+] Starting analysis of {self.apk_path}")
        print(f"[+] Output directory: {self.output_dir}")
        
        # Step 1: Basic APK information
        self._extract_basic_info()
        
        # Step 2: Extract and analyze manifest
        self._analyze_manifest()
        
        # Step 3: Extract certificates
        self._extract_certificates()
        
        # Step 4: Decompile APK
        self._decompile_apk()
        
        # Step 5: Analyze components
        self._analyze_components()
        
        # Step 6: Find API endpoints
        self._find_api_endpoints()
        
        # Step 7: Search for secrets
        self._find_secrets()
        
        # Step 8: Analyze native libraries
        self._analyze_native_libraries()
        
        # Step 9: Security analysis
        self._perform_security_analysis()
        
        # Step 10: Generate report
        self._generate_report()
        
        return self.results
    
    def _extract_basic_info(self):
        """Extract basic APK information"""
        print("[+] Extracting basic APK information...")
        
        try:
            # Get file size and basic info
            file_stats = self.apk_path.stat()
            
            self.results['apk_info'] = {
                'file_path': str(self.apk_path),
                'file_size': file_stats.st_size,
                'file_size_mb': round(file_stats.st_size / (1024 * 1024), 2),
                'modified_time': datetime.fromtimestamp(file_stats.st_mtime).isoformat()
            }
            
            # Extract using aapt if available
            if self.tools['aapt']:
                aapt_info = self._run_aapt_dump()
                self.results['apk_info'].update(aapt_info)
            
            # Extract basic info from APK structure
            with zipfile.ZipFile(self.apk_path, 'r') as apk_zip:
                file_list = apk_zip.namelist()
                
                self.results['apk_info'].update({
                    'total_files': len(file_list),
                    'has_native_code': any(f.startswith('lib/') for f in file_list),
                    'native_architectures': list(set(
                        f.split('/')[1] for f in file_list 
                        if f.startswith('lib/') and f.count('/') >= 2
                    )),
                    'dex_files': [f for f in file_list if f.endswith('.dex')],
                    'asset_files': [f for f in file_list if f.startswith('assets/')],
                    'resource_files': [f for f in file_list if f.startswith('res/')]
                })
            
            print(f"    Package: {self.results['apk_info'].get('package_name', 'Unknown')}")
            print(f"    Version: {self.results['apk_info'].get('version_name', 'Unknown')}")
            print(f"    Size: {self.results['apk_info']['file_size_mb']} MB")
            
        except Exception as e:
            print(f"[-] Error extracting basic info: {e}")
    
    def _run_aapt_dump(self) -> Dict:
        """Run aapt dump to extract APK information"""
        try:
            cmd = [self.tools['aapt'], 'dump', 'badging', str(self.apk_path)]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                return {}
            
            info = {}
            for line in result.stdout.split('\n'):
                if line.startswith('package:'):
                    # Parse package info
                    parts = line.split()
                    for part in parts:
                        if part.startswith('name='):
                            info['package_name'] = part.split('=')[1].strip("'\"")
                        elif part.startswith('versionCode='):
                            info['version_code'] = part.split('=')[1].strip("'\"")
                        elif part.startswith('versionName='):
                            info['version_name'] = part.split('=')[1].strip("'\"")
                elif line.startswith('application-label:'):
                    info['app_name'] = line.split(':', 1)[1].strip().strip("'\"")
                elif line.startswith('sdkVersion:'):
                    info['min_sdk'] = line.split(':', 1)[1].strip().strip("'\"")
                elif line.startswith('targetSdkVersion:'):
                    info['target_sdk'] = line.split(':', 1)[1].strip().strip("'\"")
            
            return info
            
        except Exception as e:
            print(f"[-] Error running aapt: {e}")
            return {}
    
    def _analyze_manifest(self):
        """Extract and analyze AndroidManifest.xml"""
        print("[+] Analyzing AndroidManifest.xml...")
        
        try:
            # Extract manifest using apktool
            if self.tools['apktool']:
                temp_dir = tempfile.mkdtemp()
                try:
                    cmd = [self.tools['apktool'], 'd', str(self.apk_path), '-o', temp_dir, '--force']
                    subprocess.run(cmd, capture_output=True, timeout=60)
                    
                    manifest_path = Path(temp_dir) / 'AndroidManifest.xml'
                    if manifest_path.exists():
                        self._parse_manifest(manifest_path)
                
                finally:
                    shutil.rmtree(temp_dir, ignore_errors=True)
            else:
                print("[-] APKTool not available for manifest extraction")
                
        except Exception as e:
            print(f"[-] Error analyzing manifest: {e}")
    
    def _parse_manifest(self, manifest_path: Path):
        """Parse AndroidManifest.xml"""
        try:
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            
            manifest_data = {
                'package': root.get('package'),
                'version_code': root.get('{http://schemas.android.com/apk/res/android}versionCode'),
                'version_name': root.get('{http://schemas.android.com/apk/res/android}versionName'),
                'permissions': [],
                'activities': [],
                'services': [],
                'receivers': [],
                'providers': [],
                'application_flags': {}
            }
            
            # Extract permissions
            for perm in root.findall('.//uses-permission'):
                perm_name = perm.get('{http://schemas.android.com/apk/res/android}name')
                if perm_name:
                    manifest_data['permissions'].append(perm_name)
            
            # Extract application flags
            app = root.find('application')
            if app is not None:
                android_ns = '{http://schemas.android.com/apk/res/android}'
                manifest_data['application_flags'] = {
                    'debuggable': app.get(f'{android_ns}debuggable', 'false') == 'true',
                    'allow_backup': app.get(f'{android_ns}allowBackup', 'true') == 'true',
                    'uses_cleartext_traffic': app.get(f'{android_ns}usesCleartextTraffic', 'true') == 'true',
                    'exported': app.get(f'{android_ns}exported', 'false') == 'true'
                }
                
                # Extract components
                for activity in app.findall('.//activity'):
                    activity_data = self._extract_component_info(activity, 'activity')
                    manifest_data['activities'].append(activity_data)
                
                for service in app.findall('.//service'):
                    service_data = self._extract_component_info(service, 'service')
                    manifest_data['services'].append(service_data)
                
                for receiver in app.findall('.//receiver'):
                    receiver_data = self._extract_component_info(receiver, 'receiver')
                    manifest_data['receivers'].append(receiver_data)
                
                for provider in app.findall('.//provider'):
                    provider_data = self._extract_component_info(provider, 'provider')
                    manifest_data['providers'].append(provider_data)
            
            self.results['manifest_analysis'] = manifest_data
            self.results['permissions'] = manifest_data['permissions']
            self.results['components'] = {
                'activities': manifest_data['activities'],
                'services': manifest_data['services'],
                'receivers': manifest_data['receivers'],
                'providers': manifest_data['providers']
            }
            
            print(f"    Found {len(manifest_data['permissions'])} permissions")
            print(f"    Found {len(manifest_data['activities'])} activities")
            print(f"    Found {len(manifest_data['services'])} services")
            
        except Exception as e:
            print(f"[-] Error parsing manifest: {e}")
    
    def _extract_component_info(self, component, component_type: str) -> Dict:
        """Extract information from a component element"""
        android_ns = '{http://schemas.android.com/apk/res/android}'
        
        info = {
            'name': component.get(f'{android_ns}name'),
            'exported': component.get(f'{android_ns}exported', 'false') == 'true',
            'enabled': component.get(f'{android_ns}enabled', 'true') == 'true',
            'intent_filters': []
        }
        
        # Extract intent filters
        for intent_filter in component.findall('.//intent-filter'):
            filter_info = {
                'actions': [action.get(f'{android_ns}name') 
                          for action in intent_filter.findall('.//action')],
                'categories': [cat.get(f'{android_ns}name') 
                             for cat in intent_filter.findall('.//category')],
                'data': []
            }
            
            for data in intent_filter.findall('.//data'):
                data_info = {
                    'scheme': data.get(f'{android_ns}scheme'),
                    'host': data.get(f'{android_ns}host'),
                    'path': data.get(f'{android_ns}path'),
                    'mime_type': data.get(f'{android_ns}mimeType')
                }
                filter_info['data'].append(data_info)
            
            info['intent_filters'].append(filter_info)
        
        return info
    
    def _extract_certificates(self):
        """Extract and analyze certificates"""
        print("[+] Extracting certificate information...")
        
        try:
            if not self.tools['keytool']:
                print("[-] keytool not available for certificate analysis")
                return
            
            cmd = [self.tools['keytool'], '-printcert', '-jarfile', str(self.apk_path)]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                cert_info = self._parse_certificate_output(result.stdout)
                self.results['certificates'] = cert_info
                print(f"    Certificate extracted: {cert_info.get('subject', 'Unknown')}")
            
        except Exception as e:
            print(f"[-] Error extracting certificates: {e}")
    
    def _parse_certificate_output(self, output: str) -> Dict:
        """Parse keytool certificate output"""
        cert_info = {}
        
        for line in output.split('\n'):
            line = line.strip()
            
            if line.startswith('Owner:'):
                cert_info['subject'] = line.split(':', 1)[1].strip()
            elif line.startswith('Issuer:'):
                cert_info['issuer'] = line.split(':', 1)[1].strip()
            elif line.startswith('Serial number:'):
                cert_info['serial_number'] = line.split(':', 1)[1].strip()
            elif line.startswith('Valid from:'):
                cert_info['valid_from'] = line.split(':', 1)[1].strip()
            elif 'until:' in line:
                cert_info['valid_until'] = line.split('until:', 1)[1].strip()
            elif line.startswith('Certificate fingerprints:'):
                cert_info['fingerprints'] = {}
            elif 'SHA1:' in line:
                cert_info.setdefault('fingerprints', {})['SHA1'] = line.split('SHA1:', 1)[1].strip()
            elif 'SHA256:' in line:
                cert_info.setdefault('fingerprints', {})['SHA256'] = line.split('SHA256:', 1)[1].strip()
        
        return cert_info
    
    def _decompile_apk(self):
        """Decompile APK using JADX"""
        print("[+] Decompiling APK with JADX...")
        
        if not self.tools['jadx']:
            print("[-] JADX not available for decompilation")
            return
        
        try:
            jadx_output = self.output_dir / 'jadx_decompiled'
            jadx_output.mkdir(exist_ok=True)
            
            cmd = [
                self.tools['jadx'],
                '--deobf',
                '--show-bad-code',
                '-d', str(jadx_output),
                str(self.apk_path)
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                self.decompiled_path = jadx_output
                print(f"    Decompiled successfully to: {jadx_output}")
            else:
                print(f"[-] JADX decompilation failed: {result.stderr}")
                
        except Exception as e:
            print(f"[-] Error during decompilation: {e}")
    
    def _analyze_components(self):
        """Analyze decompiled components for security issues"""
        print("[+] Analyzing components for security issues...")
        
        if not hasattr(self, 'decompiled_path') or not self.decompiled_path.exists():
            print("[-] No decompiled code available for component analysis")
            return
        
        try:
            # Analyze exported components for security issues
            exported_components = []
            
            for component_type, components in self.results['components'].items():
                for component in components:
                    if component.get('exported', False):
                        exported_components.append({
                            'type': component_type,
                            'name': component['name'],
                            'intent_filters': component.get('intent_filters', [])
                        })
            
            # Check for common vulnerabilities in exported components
            for component in exported_components:
                vulnerabilities = self._check_component_vulnerabilities(component)
                if vulnerabilities:
                    self.results['security_findings'].extend(vulnerabilities)
            
            print(f"    Analyzed {len(exported_components)} exported components")
            
        except Exception as e:
            print(f"[-] Error analyzing components: {e}")
    
    def _check_component_vulnerabilities(self, component: Dict) -> List[Dict]:
        """Check component for common vulnerabilities"""
        vulnerabilities = []
        
        # Check for dangerous intent filters
        for intent_filter in component.get('intent_filters', []):
            actions = intent_filter.get('actions', [])
            
            # Check for dangerous actions
            dangerous_actions = [
                'android.intent.action.MAIN',
                'android.intent.action.VIEW',
                'android.intent.action.SEND'
            ]
            
            for action in actions:
                if action in dangerous_actions and len(intent_filter.get('categories', [])) == 0:
                    vulnerabilities.append({
                        'type': 'Exported Component Vulnerability',
                        'severity': 'Medium',
                        'component': component['name'],
                        'component_type': component['type'],
                        'description': f'Exported {component["type"]} with dangerous action: {action}',
                        'action': action
                    })
        
        return vulnerabilities
    
    def _find_api_endpoints(self):
        """Find API endpoints in decompiled code"""
        print("[+] Searching for API endpoints...")
        
        if not hasattr(self, 'decompiled_path') or not self.decompiled_path.exists():
            print("[-] No decompiled code available for endpoint analysis")
            return
        
        try:
            from .endpoint_extractor import EndpointExtractor
            
            extractor = EndpointExtractor(str(self.decompiled_path))
            endpoints = extractor.extract_endpoints()
            
            self.results['api_endpoints'] = endpoints
            print(f"    Found {len(endpoints)} potential API endpoints")
            
        except Exception as e:
            print(f"[-] Error finding API endpoints: {e}")
            # Fallback to simple regex search
            self._simple_endpoint_search()
    
    def _simple_endpoint_search(self):
        """Simple regex-based endpoint search as fallback"""
        import re
        
        endpoints = []
        url_pattern = re.compile(r'https?://[^\s"\'\)]+', re.IGNORECASE)
        
        try:
            for java_file in self.decompiled_path.rglob('*.java'):
                with open(java_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                    matches = url_pattern.findall(content)
                    for match in matches:
                        endpoints.append({
                            'url': match,
                            'file': str(java_file.relative_to(self.decompiled_path)),
                            'method': 'regex_search'
                        })
            
            # Remove duplicates
            unique_endpoints = []
            seen_urls = set()
            
            for endpoint in endpoints:
                if endpoint['url'] not in seen_urls:
                    unique_endpoints.append(endpoint)
                    seen_urls.add(endpoint['url'])
            
            self.results['api_endpoints'] = unique_endpoints[:50]  # Limit to 50
            
        except Exception as e:
            print(f"[-] Error in simple endpoint search: {e}")
    
    def _find_secrets(self):
        """Find hardcoded secrets in decompiled code"""
        print("[+] Searching for hardcoded secrets...")
        
        if not hasattr(self, 'decompiled_path') or not self.decompiled_path.exists():
            print("[-] No decompiled code available for secret analysis")
            return
        
        try:
            from .secret_finder import SecretFinder
            
            finder = SecretFinder(str(self.decompiled_path))
            secrets = finder.find_secrets()
            
            self.results['secrets'] = secrets
            print(f"    Found {len(secrets)} potential secrets")
            
        except Exception as e:
            print(f"[-] Error finding secrets: {e}")
            # Fallback to simple secret search
            self._simple_secret_search()
    
    def _simple_secret_search(self):
        """Simple regex-based secret search as fallback"""
        import re
        
        secret_patterns = {
            'API Key': re.compile(r'["\']api[_-]?key["\'][\s]*[:=][\s]*["\']([^"\']{10,})["\']', re.IGNORECASE),
            'Token': re.compile(r'["\']token["\'][\s]*[:=][\s]*["\']([^"\']{10,})["\']', re.IGNORECASE),
            'Password': re.compile(r'["\']password["\'][\s]*[:=][\s]*["\']([^"\']{6,})["\']', re.IGNORECASE),
            'Secret': re.compile(r'["\']secret["\'][\s]*[:=][\s]*["\']([^"\']{10,})["\']', re.IGNORECASE)
        }
        
        secrets = []
        
        try:
            for java_file in self.decompiled_path.rglob('*.java'):
                with open(java_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                    for secret_type, pattern in secret_patterns.items():
                        matches = pattern.finditer(content)
                        for match in matches:
                            line_num = content[:match.start()].count('\n') + 1
                            secrets.append({
                                'type': secret_type,
                                'value': match.group(1),
                                'file': str(java_file.relative_to(self.decompiled_path)),
                                'line': line_num
                            })
            
            self.results['secrets'] = secrets[:100]  # Limit to 100
            
        except Exception as e:
            print(f"[-] Error in simple secret search: {e}")
    
    def _analyze_native_libraries(self):
        """Analyze native libraries"""
        print("[+] Analyzing native libraries...")
        
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as apk_zip:
                native_libs = []
                
                for file_info in apk_zip.filelist:
                    if file_info.filename.startswith('lib/') and file_info.filename.endswith('.so'):
                        lib_info = {
                            'filename': file_info.filename,
                            'architecture': file_info.filename.split('/')[1],
                            'size': file_info.file_size,
                            'compressed_size': file_info.compress_size
                        }
                        
                        # Extract and analyze strings
                        try:
                            lib_data = apk_zip.read(file_info.filename)
                            strings = self._extract_strings_from_binary(lib_data)
                            lib_info['interesting_strings'] = strings
                        except Exception as e:
                            lib_info['error'] = str(e)
                        
                        native_libs.append(lib_info)
                
                self.results['native_libraries'] = native_libs
                print(f"    Found {len(native_libs)} native libraries")
                
        except Exception as e:
            print(f"[-] Error analyzing native libraries: {e}")
    
    def _extract_strings_from_binary(self, binary_data: bytes, min_length: int = 4) -> List[str]:
        """Extract printable strings from binary data"""
        import string
        
        strings = []
        current_string = ""
        
        for byte in binary_data:
            if byte < 128 and chr(byte) in string.printable:
                current_string += chr(byte)
            else:
                if len(current_string) >= min_length:
                    # Filter for interesting strings
                    if any(keyword in current_string.lower() for keyword in 
                          ['http', 'api', 'key', 'token', 'secret', 'password', 'debug']):
                        strings.append(current_string)
                current_string = ""
        
        # Don't return too many strings
        return strings[:20]
    
    def _perform_security_analysis(self):
        """Perform comprehensive security analysis"""
        print("[+] Performing security analysis...")
        
        security_findings = []
        
        # Check manifest security issues
        manifest_findings = self._check_manifest_security()
        security_findings.extend(manifest_findings)
        
        # Check permission security issues
        permission_findings = self._check_permission_security()
        security_findings.extend(permission_findings)
        
        # Check certificate security issues
        cert_findings = self._check_certificate_security()
        security_findings.extend(cert_findings)
        
        self.results['security_findings'].extend(security_findings)
        print(f"    Found {len(security_findings)} security findings")
    
    def _check_manifest_security(self) -> List[Dict]:
        """Check manifest for security issues"""
        findings = []
        
        app_flags = self.results['manifest_analysis'].get('application_flags', {})
        
        if app_flags.get('debuggable', False):
            findings.append({
                'type': 'Debuggable Application',
                'severity': 'Medium',
                'description': 'Application is debuggable in production',
                'recommendation': 'Set android:debuggable="false" for production builds'
            })
        
        if app_flags.get('allow_backup', True):
            findings.append({
                'type': 'Backup Allowed',
                'severity': 'Low',
                'description': 'Application allows backup of data',
                'recommendation': 'Consider setting android:allowBackup="false" for sensitive apps'
            })
        
        if app_flags.get('uses_cleartext_traffic', True):
            findings.append({
                'type': 'Cleartext Traffic Allowed',
                'severity': 'Medium',
                'description': 'Application allows cleartext network traffic',
                'recommendation': 'Set android:usesCleartextTraffic="false" and use HTTPS'
            })
        
        return findings
    
    def _check_permission_security(self) -> List[Dict]:
        """Check permissions for security issues"""
        findings = []
        
        dangerous_permissions = [
            'android.permission.READ_SMS',
            'android.permission.SEND_SMS',
            'android.permission.READ_CONTACTS',
            'android.permission.WRITE_CONTACTS',
            'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.CAMERA',
            'android.permission.RECORD_AUDIO',
            'android.permission.WRITE_EXTERNAL_STORAGE'
        ]
        
        app_permissions = self.results.get('permissions', [])
        
        for permission in app_permissions:
            if permission in dangerous_permissions:
                findings.append({
                    'type': 'Dangerous Permission',
                    'severity': 'Medium',
                    'description': f'Application requests dangerous permission: {permission}',
                    'permission': permission,
                    'recommendation': 'Ensure this permission is necessary and properly justified'
                })
        
        return findings
    
    def _check_certificate_security(self) -> List[Dict]:
        """Check certificate for security issues"""
        findings = []
        
        cert_info = self.results.get('certificates')
        if not cert_info:
            return findings
        
        subject = cert_info.get('subject', '')
        
        # Check for debug certificates
        if 'debug' in subject.lower() or 'android debug' in subject.lower():
            findings.append({
                'type': 'Debug Certificate',
                'severity': 'High',
                'description': 'Application is signed with debug certificate',
                'recommendation': 'Sign application with production certificate before release'
            })
        
        # Check certificate validity
        valid_until = cert_info.get('valid_until')
        if valid_until:
            # This is a simplified check - in practice, you'd parse the date
            if 'expired' in valid_until.lower():
                findings.append({
                    'type': 'Expired Certificate',
                    'severity': 'High',
                    'description': 'Application certificate has expired',
                    'recommendation': 'Renew certificate and re-sign application'
                })
        
        return findings
    
    def _generate_report(self):
        """Generate comprehensive analysis report"""
        print("[+] Generating analysis report...")
        
        # Summary statistics
        summary = {
            'total_permissions': len(self.results.get('permissions', [])),
            'dangerous_permissions': len([
                p for p in self.results.get('permissions', [])
                if any(dangerous in p for dangerous in ['SMS', 'CONTACTS', 'LOCATION', 'CAMERA', 'AUDIO'])
            ]),
            'exported_components': sum(
                len([c for c in components if c.get('exported', False)])
                for components in self.results.get('components', {}).values()
            ),
            'security_findings': len(self.results.get('security_findings', [])),
            'api_endpoints': len(self.results.get('api_endpoints', [])),
            'secrets_found': len(self.results.get('secrets', [])),
            'native_libraries': len(self.results.get('native_libraries', []))
        }
        
        self.results['summary'] = summary
        
        # Save detailed results
        report_file = self.output_dir / 'analysis_report.json'
        with open(report_file, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        # Generate markdown report
        self._generate_markdown_report()
        
        print(f"[+] Analysis complete!")
        print(f"    Report saved to: {report_file}")
        print(f"    Found {summary['security_findings']} security findings")
        print(f"    Found {summary['api_endpoints']} API endpoints")
        print(f"    Found {summary['secrets_found']} potential secrets")
    
    def _generate_markdown_report(self):
        """Generate markdown report"""
        report_md = self.output_dir / 'analysis_report.md'
        
        with open(report_md, 'w') as f:
            f.write(f"# APK Analysis Report\n\n")
            f.write(f"**APK File:** `{self.apk_path.name}`\n")
            f.write(f"**Analysis Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Summary
            summary = self.results.get('summary', {})
            f.write("## Summary\n\n")
            f.write(f"- **Security Findings:** {summary.get('security_findings', 0)}\n")
            f.write(f"- **API Endpoints:** {summary.get('api_endpoints', 0)}\n")
            f.write(f"- **Secrets Found:** {summary.get('secrets_found', 0)}\n")
            f.write(f"- **Permissions:** {summary.get('total_permissions', 0)}\n")
            f.write(f"- **Native Libraries:** {summary.get('native_libraries', 0)}\n\n")
            
            # Security Findings
            if self.results.get('security_findings'):
                f.write("## Security Findings\n\n")
                for finding in self.results['security_findings']:
                    f.write(f"### {finding.get('type', 'Unknown')} ({finding.get('severity', 'Unknown')})\n")
                    f.write(f"{finding.get('description', 'No description')}\n\n")
                    if finding.get('recommendation'):
                        f.write(f"**Recommendation:** {finding['recommendation']}\n\n")
            
            # API Endpoints
            if self.results.get('api_endpoints'):
                f.write("## API Endpoints\n\n")
                for endpoint in self.results['api_endpoints'][:20]:  # Limit to 20
                    f.write(f"- `{endpoint.get('url', 'Unknown URL')}`\n")
                f.write("\n")
            
            # Secrets
            if self.results.get('secrets'):
                f.write("## Potential Secrets\n\n")
                for secret in self.results['secrets'][:10]:  # Limit to 10
                    f.write(f"- **{secret.get('type', 'Unknown')}:** `{secret.get('value', 'Unknown')[:50]}...`\n")
                    f.write(f"  - File: `{secret.get('file', 'Unknown')}`\n")
                f.write("\n")


def main():
    parser = argparse.ArgumentParser(description='Comprehensive APK Static Analysis Tool')
    parser.add_argument('apk_path', help='Path to APK file to analyze')
    parser.add_argument('-o', '--output', help='Output directory for analysis results')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.apk_path):
        print(f"[-] APK file not found: {args.apk_path}")
        sys.exit(1)
    
    try:
        analyzer = APKAnalyzer(args.apk_path, args.output)
        results = analyzer.analyze()
        
        print("\n" + "="*50)
        print("ANALYSIS SUMMARY")
        print("="*50)
        
        summary = results.get('summary', {})
        print(f"Security Findings: {summary.get('security_findings', 0)}")
        print(f"API Endpoints: {summary.get('api_endpoints', 0)}")
        print(f"Secrets Found: {summary.get('secrets_found', 0)}")
        print(f"Total Permissions: {summary.get('total_permissions', 0)}")
        print(f"Native Libraries: {summary.get('native_libraries', 0)}")
        
    except Exception as e:
        print(f"[-] Analysis failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
