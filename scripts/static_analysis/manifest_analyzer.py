#!/usr/bin/env python3
"""
AndroidManifest.xml Analyzer

This script performs comprehensive analysis of AndroidManifest.xml files to identify
security misconfigurations, privacy issues, and potential attack vectors.
"""

import os
import sys
import json
import argparse
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime

class ManifestAnalyzer:
    def __init__(self, manifest_path: str):
        self.manifest_path = Path(manifest_path)
        self.tree = None
        self.root = None
        self.findings = []
        self.info = {}
        
        # Android namespace
        self.android_ns = '{http://schemas.android.com/apk/res/android}'
        
        # Dangerous permissions that require user consent
        self.dangerous_permissions = {
            'android.permission.READ_CALENDAR': 'Calendar access',
            'android.permission.WRITE_CALENDAR': 'Calendar modification',
            'android.permission.CAMERA': 'Camera access',
            'android.permission.READ_CONTACTS': 'Contact reading',
            'android.permission.WRITE_CONTACTS': 'Contact modification',
            'android.permission.GET_ACCOUNTS': 'Account access',
            'android.permission.ACCESS_FINE_LOCATION': 'Precise location access',
            'android.permission.ACCESS_COARSE_LOCATION': 'Approximate location access',
            'android.permission.RECORD_AUDIO': 'Microphone access',
            'android.permission.READ_PHONE_STATE': 'Phone state reading',
            'android.permission.READ_PHONE_NUMBERS': 'Phone number reading',
            'android.permission.CALL_PHONE': 'Phone call initiation',
            'android.permission.ANSWER_PHONE_CALLS': 'Phone call answering',
            'android.permission.ADD_VOICEMAIL': 'Voicemail addition',
            'android.permission.USE_SIP': 'SIP usage',
            'android.permission.PROCESS_OUTGOING_CALLS': 'Outgoing call processing',
            'android.permission.BODY_SENSORS': 'Body sensor access',
            'android.permission.SEND_SMS': 'SMS sending',
            'android.permission.RECEIVE_SMS': 'SMS receiving',
            'android.permission.READ_SMS': 'SMS reading',
            'android.permission.RECEIVE_WAP_PUSH': 'WAP push receiving',
            'android.permission.RECEIVE_MMS': 'MMS receiving',
            'android.permission.READ_EXTERNAL_STORAGE': 'External storage reading',
            'android.permission.WRITE_EXTERNAL_STORAGE': 'External storage writing',
        }
        
        # Special permissions that can be dangerous
        self.special_permissions = {
            'android.permission.WRITE_SETTINGS': 'System settings modification',
            'android.permission.SYSTEM_ALERT_WINDOW': 'System alert window overlay',
            'android.permission.REQUEST_INSTALL_PACKAGES': 'Package installation',
            'android.permission.ACCESS_NOTIFICATION_POLICY': 'Notification policy access',
            'android.permission.BIND_NOTIFICATION_LISTENER_SERVICE': 'Notification listener',
            'android.permission.BIND_DEVICE_ADMIN': 'Device admin binding',
            'android.permission.BIND_ACCESSIBILITY_SERVICE': 'Accessibility service',
            'android.permission.MANAGE_DOCUMENTS': 'Document management',
        }
        
        # Signature-level permissions
        self.signature_permissions = {
            'android.permission.INSTALL_PACKAGES': 'Package installation (system)',
            'android.permission.DELETE_PACKAGES': 'Package deletion (system)',
            'android.permission.CLEAR_APP_CACHE': 'App cache clearing (system)',
            'android.permission.ACCESS_SUPERUSER': 'Superuser access',
            'android.permission.WRITE_SECURE_SETTINGS': 'Secure settings modification',
        }
    
    def analyze(self) -> Dict:
        """Perform comprehensive manifest analysis"""
        print(f"[+] Analyzing AndroidManifest.xml: {self.manifest_path}")
        
        if not self.manifest_path.exists():
            print(f"[-] Manifest file not found: {self.manifest_path}")
            return {}
        
        try:
            # Parse XML
            self.tree = ET.parse(self.manifest_path)
            self.root = self.tree.getroot()
            
            # Extract basic information
            self._extract_basic_info()
            
            # Analyze different aspects
            self._analyze_permissions()
            self._analyze_application_flags()
            self._analyze_components()
            self._analyze_intent_filters()
            self._analyze_providers()
            self._analyze_backup_settings()
            self._analyze_network_security()
            self._analyze_debugging_flags()
            self._analyze_custom_permissions()
            
            # Generate final report
            return self._generate_results()
            
        except ET.ParseError as e:
            print(f"[-] Failed to parse manifest XML: {e}")
            return {}
        except Exception as e:
            print(f"[-] Error during analysis: {e}")
            return {}
    
    def _extract_basic_info(self):
        """Extract basic application information"""
        self.info = {
            'package_name': self.root.get('package'),
            'version_code': self.root.get(f'{self.android_ns}versionCode'),
            'version_name': self.root.get(f'{self.android_ns}versionName'),
            'shared_user_id': self.root.get(f'{self.android_ns}sharedUserId'),
            'install_location': self.root.get(f'{self.android_ns}installLocation'),
        }
        
        # Extract SDK versions
        uses_sdk = self.root.find('uses-sdk')
        if uses_sdk is not None:
            self.info.update({
                'min_sdk': uses_sdk.get(f'{self.android_ns}minSdkVersion'),
                'target_sdk': uses_sdk.get(f'{self.android_ns}targetSdkVersion'),
                'max_sdk': uses_sdk.get(f'{self.android_ns}maxSdkVersion'),
            })
        
        print(f"    Package: {self.info['package_name']}")
        print(f"    Version: {self.info['version_name']} ({self.info['version_code']})")
    
    def _analyze_permissions(self):
        """Analyze declared permissions"""
        print("[+] Analyzing permissions...")
        
        permissions = []
        dangerous_count = 0
        special_count = 0
        
        for perm in self.root.findall('uses-permission'):
            perm_name = perm.get(f'{self.android_ns}name')
            if perm_name:
                permission_info = {
                    'name': perm_name,
                    'max_sdk': perm.get(f'{self.android_ns}maxSdkVersion'),
                    'type': 'normal'
                }
                
                # Categorize permission
                if perm_name in self.dangerous_permissions:
                    permission_info['type'] = 'dangerous'
                    permission_info['description'] = self.dangerous_permissions[perm_name]
                    dangerous_count += 1
                    
                    self._add_finding(
                        'Dangerous Permission',
                        'Medium',
                        f'App requests dangerous permission: {perm_name}',
                        f'Permission allows: {self.dangerous_permissions[perm_name]}',
                        'Ensure this permission is necessary and properly justified to users'
                    )
                
                elif perm_name in self.special_permissions:
                    permission_info['type'] = 'special'
                    permission_info['description'] = self.special_permissions[perm_name]
                    special_count += 1
                    
                    self._add_finding(
                        'Special Permission',
                        'Medium',
                        f'App requests special permission: {perm_name}',
                        f'Permission allows: {self.special_permissions[perm_name]}',
                        'Special permissions require user approval through settings'
                    )
                
                elif perm_name in self.signature_permissions:
                    permission_info['type'] = 'signature'
                    permission_info['description'] = self.signature_permissions[perm_name]
                    
                    self._add_finding(
                        'Signature Permission',
                        'High',
                        f'App requests signature-level permission: {perm_name}',
                        f'Permission allows: {self.signature_permissions[perm_name]}',
                        'Signature permissions are only granted to system apps or apps signed with platform key'
                    )
                
                permissions.append(permission_info)
        
        self.info['permissions'] = permissions
        self.info['permission_counts'] = {
            'total': len(permissions),
            'dangerous': dangerous_count,
            'special': special_count
        }
        
        print(f"    Found {len(permissions)} permissions ({dangerous_count} dangerous, {special_count} special)")
    
    def _analyze_application_flags(self):
        """Analyze application-level security flags"""
        print("[+] Analyzing application flags...")
        
        app = self.root.find('application')
        if app is None:
            return
        
        flags = {
            'debuggable': app.get(f'{self.android_ns}debuggable', 'false') == 'true',
            'allow_backup': app.get(f'{self.android_ns}allowBackup', 'true') == 'true',
            'uses_cleartext_traffic': app.get(f'{self.android_ns}usesCleartextTraffic', 'true') == 'true',
            'extract_native_libs': app.get(f'{self.android_ns}extractNativeLibs', 'true') == 'true',
            'has_fragile_user_data': app.get(f'{self.android_ns}hasFragileUserData', 'false') == 'true',
            'large_heap': app.get(f'{self.android_ns}largeHeap', 'false') == 'true',
            'test_only': app.get(f'{self.android_ns}testOnly', 'false') == 'true',
        }
        
        self.info['application_flags'] = flags
        
        # Check for security issues
        if flags['debuggable']:
            self._add_finding(
                'Debuggable Application',
                'High' if self._is_production_app() else 'Medium',
                'Application is marked as debuggable',
                'android:debuggable="true" allows debugging in production',
                'Set android:debuggable="false" for production releases'
            )
        
        if flags['allow_backup']:
            self._add_finding(
                'Backup Allowed',
                'Low',
                'Application allows data backup',
                'android:allowBackup="true" permits ADB backup/restore',
                'Consider setting android:allowBackup="false" for sensitive applications'
            )
        
        if flags['uses_cleartext_traffic']:
            self._add_finding(
                'Cleartext Traffic Allowed',
                'Medium',
                'Application allows cleartext network traffic',
                'android:usesCleartextTraffic="true" permits HTTP connections',
                'Set android:usesCleartextTraffic="false" and use HTTPS exclusively'
            )
        
        if flags['test_only']:
            self._add_finding(
                'Test-Only Application',
                'High',
                'Application is marked as test-only',
                'android:testOnly="true" should not be used in production',
                'Remove android:testOnly for production releases'
            )
    
    def _analyze_components(self):
        """Analyze application components"""
        print("[+] Analyzing application components...")
        
        app = self.root.find('application')
        if app is None:
            return
        
        components = {
            'activities': [],
            'services': [],
            'receivers': [],
            'providers': []
        }
        
        # Analyze activities
        for activity in app.findall('activity'):
            activity_info = self._analyze_component(activity, 'activity')
            components['activities'].append(activity_info)
        
        # Analyze services
        for service in app.findall('service'):
            service_info = self._analyze_component(service, 'service')
            components['services'].append(service_info)
        
        # Analyze receivers
        for receiver in app.findall('receiver'):
            receiver_info = self._analyze_component(receiver, 'receiver')
            components['receivers'].append(receiver_info)
        
        # Analyze providers
        for provider in app.findall('provider'):
            provider_info = self._analyze_component(provider, 'provider')
            components['providers'].append(provider_info)
        
        self.info['components'] = components
        
        # Check for exported components without protection
        self._check_exported_components(components)
    
    def _analyze_component(self, component, component_type: str) -> Dict:
        """Analyze individual component"""
        info = {
            'name': component.get(f'{self.android_ns}name'),
            'exported': component.get(f'{self.android_ns}exported'),
            'enabled': component.get(f'{self.android_ns}enabled', 'true') == 'true',
            'permission': component.get(f'{self.android_ns}permission'),
            'intent_filters': []
        }
        
        # Determine if component is exported
        intent_filters = component.findall('intent-filter')
        has_intent_filters = len(intent_filters) > 0
        
        if info['exported'] is None:
            # Default export behavior
            info['exported'] = has_intent_filters
        else:
            info['exported'] = info['exported'] == 'true'
        
        # Analyze intent filters
        for intent_filter in intent_filters:
            filter_info = self._analyze_intent_filter(intent_filter)
            info['intent_filters'].append(filter_info)
        
        # Additional component-specific analysis
        if component_type == 'provider':
            info.update(self._analyze_provider_specific(component))
        elif component_type == 'service':
            info.update(self._analyze_service_specific(component))
        
        return info
    
    def _analyze_intent_filter(self, intent_filter) -> Dict:
        """Analyze intent filter"""
        filter_info = {
            'actions': [],
            'categories': [],
            'data': []
        }
        
        # Extract actions
        for action in intent_filter.findall('action'):
            action_name = action.get(f'{self.android_ns}name')
            if action_name:
                filter_info['actions'].append(action_name)
        
        # Extract categories
        for category in intent_filter.findall('category'):
            category_name = category.get(f'{self.android_ns}name')
            if category_name:
                filter_info['categories'].append(category_name)
        
        # Extract data specifications
        for data in intent_filter.findall('data'):
            data_info = {
                'scheme': data.get(f'{self.android_ns}scheme'),
                'host': data.get(f'{self.android_ns}host'),
                'port': data.get(f'{self.android_ns}port'),
                'path': data.get(f'{self.android_ns}path'),
                'path_pattern': data.get(f'{self.android_ns}pathPattern'),
                'path_prefix': data.get(f'{self.android_ns}pathPrefix'),
                'mime_type': data.get(f'{self.android_ns}mimeType')
            }
            filter_info['data'].append(data_info)
        
        return filter_info
    
    def _analyze_provider_specific(self, provider) -> Dict:
        """Analyze provider-specific attributes"""
        return {
            'authorities': provider.get(f'{self.android_ns}authorities'),
            'grant_uri_permissions': provider.get(f'{self.android_ns}grantUriPermissions', 'false') == 'true',
            'read_permission': provider.get(f'{self.android_ns}readPermission'),
            'write_permission': provider.get(f'{self.android_ns}writePermission'),
            'multiprocess': provider.get(f'{self.android_ns}multiprocess', 'false') == 'true'
        }
    
    def _analyze_service_specific(self, service) -> Dict:
        """Analyze service-specific attributes"""
        return {
            'isolated_process': service.get(f'{self.android_ns}isolatedProcess', 'false') == 'true',
            'foreground_service_type': service.get(f'{self.android_ns}foregroundServiceType')
        }
    
    def _check_exported_components(self, components: Dict):
        """Check for security issues with exported components"""
        for component_type, component_list in components.items():
            for component in component_list:
                if component.get('exported', False):
                    self._check_exported_component_security(component, component_type)
    
    def _check_exported_component_security(self, component: Dict, component_type: str):
        """Check security of exported component"""
        component_name = component.get('name', 'Unknown')
        permission = component.get('permission')
        
        # Check if exported without permission protection
        if not permission:
            severity = 'Medium'
            if component_type == 'provider':
                severity = 'High'  # Providers are more sensitive
            
            self._add_finding(
                f'Unprotected Exported {component_type.title()}',
                severity,
                f'Exported {component_type} without permission protection: {component_name}',
                f'Component can be accessed by any application on the device',
                f'Add android:permission attribute or set android:exported="false"'
            )
        
        # Check for dangerous intent filter combinations
        for intent_filter in component.get('intent_filters', []):
            self._check_dangerous_intent_filter(intent_filter, component_name, component_type)
    
    def _check_dangerous_intent_filter(self, intent_filter: Dict, component_name: str, component_type: str):
        """Check for dangerous intent filter patterns"""
        actions = intent_filter.get('actions', [])
        categories = intent_filter.get('categories', [])
        
        # Check for overly broad intent filters
        if 'android.intent.action.MAIN' in actions and not categories:
            self._add_finding(
                'Overly Broad Intent Filter',
                'Medium',
                f'Intent filter with MAIN action but no category in {component_name}',
                'This may allow unintended component access',
                'Add appropriate categories to intent filters'
            )
        
        # Check for dangerous action combinations
        dangerous_actions = [
            'android.intent.action.BOOT_COMPLETED',
            'android.intent.action.PACKAGE_INSTALL',
            'android.intent.action.PACKAGE_REMOVED',
            'android.intent.action.SMS_RECEIVED'
        ]
        
        for action in actions:
            if action in dangerous_actions:
                self._add_finding(
                    'Sensitive Intent Action',
                    'Medium',
                    f'Component {component_name} handles sensitive action: {action}',
                    'This action provides access to sensitive system events',
                    'Ensure proper validation and security measures are implemented'
                )
    
    def _analyze_intent_filters(self):
        """Analyze intent filters across all components"""
        print("[+] Analyzing intent filters...")
        
        # This is already covered in component analysis
        # but we can add specific intent filter security checks here
        pass
    
    def _analyze_providers(self):
        """Analyze content providers specifically"""
        print("[+] Analyzing content providers...")
        
        app = self.root.find('application')
        if app is None:
            return
        
        providers = app.findall('provider')
        
        for provider in providers:
            authorities = provider.get(f'{self.android_ns}authorities')
            exported = provider.get(f'{self.android_ns}exported')
            grant_uri_perms = provider.get(f'{self.android_ns}grantUriPermissions', 'false') == 'true'
            
            if exported == 'true' or (exported is None and provider.findall('intent-filter')):
                # Check for SQL injection vulnerabilities
                self._add_finding(
                    'Exported Content Provider',
                    'High',
                    f'Content provider with authorities "{authorities}" is exported',
                    'Exported providers can be accessed by other applications',
                    'Implement proper input validation and access controls'
                )
            
            if grant_uri_perms:
                self._add_finding(
                    'URI Permission Grants',
                    'Medium',
                    f'Provider "{authorities}" grants URI permissions',
                    'grantUriPermissions="true" allows dynamic permission granting',
                    'Ensure URI permissions are granted securely'
                )
    
    def _analyze_backup_settings(self):
        """Analyze backup and restore settings"""
        print("[+] Analyzing backup settings...")
        
        app = self.root.find('application')
        if app is None:
            return
        
        allow_backup = app.get(f'{self.android_ns}allowBackup', 'true') == 'true'
        backup_agent = app.get(f'{self.android_ns}backupAgent')
        full_backup_content = app.get(f'{self.android_ns}fullBackupContent')
        
        backup_info = {
            'allow_backup': allow_backup,
            'backup_agent': backup_agent,
            'full_backup_content': full_backup_content
        }
        
        self.info['backup_settings'] = backup_info
        
        if allow_backup and not full_backup_content:
            self._add_finding(
                'Unrestricted Backup',
                'Low',
                'Application allows backup without restrictions',
                'All application data can be backed up via ADB',
                'Consider implementing fullBackupContent rules or disabling backup'
            )
    
    def _analyze_network_security(self):
        """Analyze network security configuration"""
        print("[+] Analyzing network security settings...")
        
        app = self.root.find('application')
        if app is None:
            return
        
        network_config = None
        uses_cleartext = app.get(f'{self.android_ns}usesCleartextTraffic', 'true') == 'true'
        
        # Look for network security config
        for meta_data in app.findall('meta-data'):
            if meta_data.get(f'{self.android_ns}name') == 'android.security.net.config':
                network_config = meta_data.get(f'{self.android_ns}resource')
                break
        
        network_info = {
            'uses_cleartext_traffic': uses_cleartext,
            'network_security_config': network_config
        }
        
        self.info['network_security'] = network_info
        
        if not network_config and uses_cleartext:
            self._add_finding(
                'No Network Security Config',
                'Medium',
                'Application allows cleartext traffic without network security config',
                'No additional network security policies are enforced',
                'Implement network security configuration to control TLS settings'
            )
    
    def _analyze_debugging_flags(self):
        """Analyze debugging-related settings"""
        print("[+] Analyzing debugging settings...")
        
        app = self.root.find('application')
        if app is None:
            return
        
        debuggable = app.get(f'{self.android_ns}debuggable', 'false') == 'true'
        test_only = app.get(f'{self.android_ns}testOnly', 'false') == 'true'
        
        debug_info = {
            'debuggable': debuggable,
            'test_only': test_only
        }
        
        self.info['debug_settings'] = debug_info
        
        # Additional debugging checks are handled in application flags analysis
    
    def _analyze_custom_permissions(self):
        """Analyze custom permissions defined by the app"""
        print("[+] Analyzing custom permissions...")
        
        custom_permissions = []
        
        for permission in self.root.findall('permission'):
            perm_info = {
                'name': permission.get(f'{self.android_ns}name'),
                'label': permission.get(f'{self.android_ns}label'),
                'description': permission.get(f'{self.android_ns}description'),
                'protection_level': permission.get(f'{self.android_ns}protectionLevel', 'normal'),
                'permission_group': permission.get(f'{self.android_ns}permissionGroup')
            }
            custom_permissions.append(perm_info)
        
        self.info['custom_permissions'] = custom_permissions
        
        # Check for weak custom permissions
        for perm in custom_permissions:
            if perm['protection_level'] == 'normal':
                self._add_finding(
                    'Weak Custom Permission',
                    'Low',
                    f'Custom permission "{perm["name"]}" has normal protection level',
                    'Normal permissions are automatically granted to requesting apps',
                    'Use signature or dangerous protection level for sensitive permissions'
                )
    
    def _is_production_app(self) -> bool:
        """Determine if this appears to be a production application"""
        package_name = self.info.get('package_name', '')
        
        # Check for debug/test indicators
        debug_indicators = ['debug', 'test', 'dev', 'staging']
        
        return not any(indicator in package_name.lower() for indicator in debug_indicators)
    
    def _add_finding(self, finding_type: str, severity: str, title: str, 
                     description: str, recommendation: str):
        """Add a security finding"""
        finding = {
            'type': finding_type,
            'severity': severity,
            'title': title,
            'description': description,
            'recommendation': recommendation
        }
        self.findings.append(finding)
    
    def _generate_results(self) -> Dict:
        """Generate final analysis results"""
        results = {
            'manifest_path': str(self.manifest_path),
            'analysis_date': datetime.now().isoformat(),
            'application_info': self.info,
            'security_findings': self.findings,
            'summary': {
                'total_findings': len(self.findings),
                'by_severity': self._get_findings_by_severity(),
                'components_analyzed': self._count_components(),
                'permissions_analyzed': len(self.info.get('permissions', []))
            }
        }
        
        return results
    
    def _get_findings_by_severity(self) -> Dict[str, int]:
        """Get count of findings by severity"""
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        
        for finding in self.findings:
            severity = finding.get('severity', 'Low')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        return severity_counts
    
    def _count_components(self) -> Dict[str, int]:
        """Count analyzed components"""
        components = self.info.get('components', {})
        
        return {
            'activities': len(components.get('activities', [])),
            'services': len(components.get('services', [])),
            'receivers': len(components.get('receivers', [])),
            'providers': len(components.get('providers', []))
        }
    
    def save_results(self, output_file: str, results: Dict):
        """Save analysis results to file"""
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"[+] Results saved to {output_file}")
    
    def generate_report(self, output_file: str, results: Dict):
        """Generate human-readable report"""
        with open(output_file, 'w') as f:
            f.write("# AndroidManifest.xml Security Analysis Report\n\n")
            
            app_info = results['application_info']
            f.write(f"**Package:** {app_info.get('package_name', 'Unknown')}\n")
            f.write(f"**Version:** {app_info.get('version_name', 'Unknown')} ({app_info.get('version_code', 'Unknown')})\n")
            f.write(f"**Analysis Date:** {results['analysis_date']}\n\n")
            
            # Summary
            summary = results['summary']
            f.write("## Summary\n\n")
            f.write(f"- **Total Findings:** {summary['total_findings']}\n")
            f.write(f"- **Permissions:** {summary['permissions_analyzed']}\n")
            f.write(f"- **Components:** {sum(summary['components_analyzed'].values())}\n\n")
            
            # Severity breakdown
            severity_counts = summary['by_severity']
            f.write("### Findings by Severity\n\n")
            for severity, count in severity_counts.items():
                if count > 0:
                    f.write(f"- **{severity}:** {count}\n")
            f.write("\n")
            
            # Security findings
            if results['security_findings']:
                f.write("## Security Findings\n\n")
                
                current_severity = None
                for finding in sorted(results['security_findings'], 
                                    key=lambda x: ['Critical', 'High', 'Medium', 'Low'].index(x['severity'])):
                    
                    if finding['severity'] != current_severity:
                        current_severity = finding['severity']
                        f.write(f"### {current_severity} Severity\n\n")
                    
                    f.write(f"#### {finding['title']}\n")
                    f.write(f"**Type:** {finding['type']}\n\n")
                    f.write(f"**Description:** {finding['description']}\n\n")
                    f.write(f"**Recommendation:** {finding['recommendation']}\n\n")
                    f.write("---\n\n")
            
            # Application info
            f.write("## Application Information\n\n")
            
            # Permissions
            permissions = app_info.get('permissions', [])
            if permissions:
                f.write("### Permissions\n\n")
                
                dangerous_perms = [p for p in permissions if p.get('type') == 'dangerous']
                if dangerous_perms:
                    f.write("#### Dangerous Permissions\n\n")
                    for perm in dangerous_perms:
                        f.write(f"- `{perm['name']}` - {perm.get('description', 'No description')}\n")
                    f.write("\n")
                
                special_perms = [p for p in permissions if p.get('type') == 'special']
                if special_perms:
                    f.write("#### Special Permissions\n\n")
                    for perm in special_perms:
                        f.write(f"- `{perm['name']}` - {perm.get('description', 'No description')}\n")
                    f.write("\n")
            
            # Components
            components = app_info.get('components', {})
            f.write("### Components\n\n")
            
            for component_type, component_list in components.items():
                if component_list:
                    exported_count = len([c for c in component_list if c.get('exported', False)])
                    f.write(f"- **{component_type.title()}:** {len(component_list)} total, {exported_count} exported\n")
            
            f.write("\n")


def main():
    parser = argparse.ArgumentParser(description='Analyze AndroidManifest.xml for security issues')
    parser.add_argument('manifest_path', help='Path to AndroidManifest.xml file')
    parser.add_argument('-o', '--output', help='Output file for JSON results')
    parser.add_argument('-r', '--report', help='Output file for human-readable report')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.manifest_path):
        print(f"[-] Manifest file not found: {args.manifest_path}")
        sys.exit(1)
    
    try:
        analyzer = ManifestAnalyzer(args.manifest_path)
        results = analyzer.analyze()
        
        if not results:
            print("[-] Analysis failed")
            sys.exit(1)
        
        # Save results
        if args.output:
            analyzer.save_results(args.output, results)
        else:
            output_file = f"{Path(args.manifest_path).stem}_analysis.json"
            analyzer.save_results(output_file, results)
        
        # Generate report
        if args.report:
            analyzer.generate_report(args.report, results)
        else:
            report_file = f"{Path(args.manifest_path).stem}_report.md"
            analyzer.generate_report(report_file, results)
        
        print(f"\n[+] Analysis complete!")
        
        summary = results['summary']
        print(f"    Total findings: {summary['total_findings']}")
        print(f"    Permissions analyzed: {summary['permissions_analyzed']}")
        print(f"    Components analyzed: {sum(summary['components_analyzed'].values())}")
        
        # Print severity breakdown
        severity_counts = summary['by_severity']
        if any(count > 0 for count in severity_counts.values()):
            print(f"\n[+] Findings by severity:")
            for severity, count in severity_counts.items():
                if count > 0:
                    print(f"    {severity}: {count}")
        
    except Exception as e:
        print(f"[-] Analysis failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
