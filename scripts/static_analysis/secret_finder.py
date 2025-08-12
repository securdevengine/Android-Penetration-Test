#!/usr/bin/env python3
"""
Secret Finder for Android APKs

This script searches for hardcoded secrets, API keys, tokens, and other sensitive
information in decompiled Android applications using pattern matching and
entropy analysis.
"""

import re
import os
import json
import argparse
import base64
import hashlib
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple
import string
import math
from collections import Counter

class SecretFinder:
    def __init__(self, source_path: str):
        self.source_path = Path(source_path)
        self.secrets = []
        
        # Secret patterns with descriptions and severity levels
        self.secret_patterns = {
            'api_key': {
                'patterns': [
                    re.compile(r'["\']api[_-]?key["\'][\s]*[:=][\s]*["\']([A-Za-z0-9+/=]{10,})["\']', re.IGNORECASE),
                    re.compile(r'apikey[\s]*[:=][\s]*["\']([A-Za-z0-9+/=]{10,})["\']', re.IGNORECASE),
                    re.compile(r'api[_-]key[\s]*=[\s]*["\']([A-Za-z0-9+/=]{10,})["\']', re.IGNORECASE),
                ],
                'description': 'API Key',
                'severity': 'High'
            },
            'aws_access_key': {
                'patterns': [
                    re.compile(r'AKIA[0-9A-Z]{16}', re.IGNORECASE),
                    re.compile(r'["\']aws[_-]?access[_-]?key[_-]?id["\'][\s]*[:=][\s]*["\']([A-Z0-9]{20})["\']', re.IGNORECASE),
                ],
                'description': 'AWS Access Key',
                'severity': 'Critical'
            },
            'aws_secret_key': {
                'patterns': [
                    re.compile(r'["\']aws[_-]?secret[_-]?access[_-]?key["\'][\s]*[:=][\s]*["\']([A-Za-z0-9+/=]{40})["\']', re.IGNORECASE),
                ],
                'description': 'AWS Secret Access Key',
                'severity': 'Critical'
            },
            'google_api_key': {
                'patterns': [
                    re.compile(r'AIza[0-9A-Za-z\\-_]{35}', re.IGNORECASE),
                    re.compile(r'["\']google[_-]?api[_-]?key["\'][\s]*[:=][\s]*["\']([A-Za-z0-9_-]{39})["\']', re.IGNORECASE),
                ],
                'description': 'Google API Key',
                'severity': 'High'
            },
            'firebase_key': {
                'patterns': [
                    re.compile(r'["\']firebase[_-]?api[_-]?key["\'][\s]*[:=][\s]*["\']([A-Za-z0-9_-]{39})["\']', re.IGNORECASE),
                    re.compile(r'["\']firebase[_-]?database[_-]?url["\'][\s]*[:=][\s]*["\']([^"\']+)["\']', re.IGNORECASE),
                ],
                'description': 'Firebase API Key/URL',
                'severity': 'High'
            },
            'jwt_secret': {
                'patterns': [
                    re.compile(r'["\']jwt[_-]?secret["\'][\s]*[:=][\s]*["\']([A-Za-z0-9+/=]{20,})["\']', re.IGNORECASE),
                    re.compile(r'["\']jwt[_-]?key["\'][\s]*[:=][\s]*["\']([A-Za-z0-9+/=]{20,})["\']', re.IGNORECASE),
                ],
                'description': 'JWT Secret',
                'severity': 'High'
            },
            'database_password': {
                'patterns': [
                    re.compile(r'["\']db[_-]?password["\'][\s]*[:=][\s]*["\']([^"\']{6,})["\']', re.IGNORECASE),
                    re.compile(r'["\']database[_-]?password["\'][\s]*[:=][\s]*["\']([^"\']{6,})["\']', re.IGNORECASE),
                    re.compile(r'["\']mysql[_-]?password["\'][\s]*[:=][\s]*["\']([^"\']{6,})["\']', re.IGNORECASE),
                ],
                'description': 'Database Password',
                'severity': 'Critical'
            },
            'database_url': {
                'patterns': [
                    re.compile(r'["\']database[_-]?url["\'][\s]*[:=][\s]*["\']([^"\']+://[^"\']+)["\']', re.IGNORECASE),
                    re.compile(r'jdbc:[^"\'\\s]+://[^"\'\\s]+', re.IGNORECASE),
                ],
                'description': 'Database Connection URL',
                'severity': 'High'
            },
            'private_key': {
                'patterns': [
                    re.compile(r'-----BEGIN[\s\w]*PRIVATE KEY-----', re.IGNORECASE),
                    re.compile(r'["\']private[_-]?key["\'][\s]*[:=][\s]*["\']([A-Za-z0-9+/=\n\r]{100,})["\']', re.IGNORECASE),
                ],
                'description': 'Private Key',
                'severity': 'Critical'
            },
            'oauth_token': {
                'patterns': [
                    re.compile(r'["\']oauth[_-]?token["\'][\s]*[:=][\s]*["\']([A-Za-z0-9+/=]{20,})["\']', re.IGNORECASE),
                    re.compile(r'["\']access[_-]?token["\'][\s]*[:=][\s]*["\']([A-Za-z0-9+/=]{20,})["\']', re.IGNORECASE),
                ],
                'description': 'OAuth/Access Token',
                'severity': 'High'
            },
            'encryption_key': {
                'patterns': [
                    re.compile(r'["\']encryption[_-]?key["\'][\s]*[:=][\s]*["\']([A-Za-z0-9+/=]{16,})["\']', re.IGNORECASE),
                    re.compile(r'["\']aes[_-]?key["\'][\s]*[:=][\s]*["\']([A-Za-z0-9+/=]{16,})["\']', re.IGNORECASE),
                ],
                'description': 'Encryption Key',
                'severity': 'Critical'
            },
            'generic_secret': {
                'patterns': [
                    re.compile(r'["\']secret["\'][\s]*[:=][\s]*["\']([A-Za-z0-9+/=]{10,})["\']', re.IGNORECASE),
                    re.compile(r'["\']password["\'][\s]*[:=][\s]*["\']([^"\']{6,})["\']', re.IGNORECASE),
                    re.compile(r'["\']token["\'][\s]*[:=][\s]*["\']([A-Za-z0-9+/=]{10,})["\']', re.IGNORECASE),
                ],
                'description': 'Generic Secret/Password/Token',
                'severity': 'Medium'
            },
            'url_with_credentials': {
                'patterns': [
                    re.compile(r'https?://[^:]+:[^@]+@[^\s"\']+', re.IGNORECASE),
                    re.compile(r'[a-z]+://[^:]+:[^@]+@[^\s"\']+', re.IGNORECASE),
                ],
                'description': 'URL with Embedded Credentials',
                'severity': 'High'
            }
        }
        
        # File extensions to search
        self.search_extensions = {'.java', '.kt', '.xml', '.json', '.properties', '.yaml', '.yml', '.conf', '.config'}
        
        # Skip common false positives
        self.false_positive_patterns = [
            re.compile(r'^(test|example|sample|demo|placeholder)', re.IGNORECASE),
            re.compile(r'^[0-9]+$'),  # Just numbers
            re.compile(r'^[a-f0-9]{32}$'),  # MD5 hash
            re.compile(r'^[a-f0-9]{40}$'),  # SHA1 hash
            re.compile(r'^[a-f0-9]{64}$'),  # SHA256 hash
        ]
        
        # Common placeholder values to ignore
        self.placeholder_values = {
            'your_api_key', 'your_secret', 'your_token', 'your_password',
            'api_key_here', 'secret_here', 'token_here', 'password_here',
            'replace_with_your_key', 'enter_your_key', 'insert_your_key',
            'xxxx', 'yyyy', 'zzzz', '****', '----', '====',
            'null', 'none', 'empty', 'todo', 'fixme', 'changeme'
        }
    
    def find_secrets(self) -> List[Dict]:
        """Find all secrets in the source code"""
        print(f"[+] Searching for secrets in {self.source_path}")
        
        if not self.source_path.exists():
            print(f"[-] Source path does not exist: {self.source_path}")
            return []
        
        # Search in different file types
        self._search_in_files()
        
        # Perform entropy analysis for high-entropy strings
        self._entropy_analysis()
        
        # Filter false positives
        self._filter_false_positives()
        
        # Deduplicate and rank secrets
        self._deduplicate_and_rank()
        
        print(f"[+] Found {len(self.secrets)} potential secrets")
        return self.secrets
    
    def _search_in_files(self):
        """Search for secrets in files"""
        print("[+] Scanning files for secret patterns...")
        
        all_files = []
        for ext in self.search_extensions:
            all_files.extend(list(self.source_path.rglob(f'*{ext}')))
        
        print(f"    Found {len(all_files)} files to scan")
        
        for file_path in all_files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                self._scan_file_content(content, file_path)
                
            except Exception as e:
                print(f"[-] Error processing {file_path}: {e}")
    
    def _scan_file_content(self, content: str, file_path: Path):
        """Scan file content for secret patterns"""
        lines = content.split('\n')
        
        for secret_type, secret_info in self.secret_patterns.items():
            for pattern in secret_info['patterns']:
                matches = pattern.finditer(content)
                
                for match in matches:
                    secret_value = match.group(1) if match.groups() else match.group(0)
                    
                    # Skip if it looks like a placeholder
                    if self._is_placeholder(secret_value):
                        continue
                    
                    # Find line number
                    line_num = content[:match.start()].count('\n') + 1
                    line_content = lines[line_num - 1] if line_num <= len(lines) else ""
                    
                    secret_data = {
                        'type': secret_type,
                        'description': secret_info['description'],
                        'severity': secret_info['severity'],
                        'value': secret_value,
                        'file': str(file_path.relative_to(self.source_path)),
                        'line_number': line_num,
                        'line_content': line_content.strip(),
                        'confidence': self._calculate_confidence(secret_value, secret_type),
                        'entropy': self._calculate_entropy(secret_value),
                        'length': len(secret_value)
                    }
                    
                    self.secrets.append(secret_data)
    
    def _entropy_analysis(self):
        """Perform entropy analysis to find high-entropy strings"""
        print("[+] Performing entropy analysis...")
        
        # High-entropy string patterns
        entropy_patterns = [
            re.compile(r'["\']([A-Za-z0-9+/=]{20,})["\']'),  # Base64-like strings
            re.compile(r'["\']([A-Fa-f0-9]{32,})["\']'),      # Hex strings
            re.compile(r'["\']([A-Za-z0-9_-]{20,})["\']'),    # Mixed alphanumeric
        ]
        
        high_entropy_threshold = 4.5  # Entropy threshold for suspicious strings
        
        all_files = []
        for ext in self.search_extensions:
            all_files.extend(list(self.source_path.rglob(f'*{ext}')))
        
        for file_path in all_files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                for pattern in entropy_patterns:
                    matches = pattern.finditer(content)
                    
                    for match in matches:
                        string_value = match.group(1)
                        entropy = self._calculate_entropy(string_value)
                        
                        if entropy >= high_entropy_threshold and len(string_value) >= 20:
                            # Skip if already found by other patterns
                            if any(s['value'] == string_value for s in self.secrets):
                                continue
                            
                            # Skip if it looks like a placeholder
                            if self._is_placeholder(string_value):
                                continue
                            
                            line_num = content[:match.start()].count('\n') + 1
                            lines = content.split('\n')
                            line_content = lines[line_num - 1] if line_num <= len(lines) else ""
                            
                            secret_data = {
                                'type': 'high_entropy_string',
                                'description': 'High Entropy String (Potential Secret)',
                                'severity': 'Medium',
                                'value': string_value,
                                'file': str(file_path.relative_to(self.source_path)),
                                'line_number': line_num,
                                'line_content': line_content.strip(),
                                'confidence': min(entropy / 6.0, 1.0),  # Normalize to 0-1
                                'entropy': entropy,
                                'length': len(string_value)
                            }
                            
                            self.secrets.append(secret_data)
                            
            except Exception as e:
                continue
    
    def _calculate_entropy(self, string: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not string:
            return 0
        
        # Count character frequencies
        char_counts = Counter(string)
        string_length = len(string)
        
        # Calculate entropy
        entropy = 0
        for count in char_counts.values():
            probability = count / string_length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _calculate_confidence(self, value: str, secret_type: str) -> float:
        """Calculate confidence score for a secret"""
        confidence = 0.5  # Base confidence
        
        # Length-based confidence
        if len(value) >= 32:
            confidence += 0.2
        elif len(value) >= 20:
            confidence += 0.1
        
        # Entropy-based confidence
        entropy = self._calculate_entropy(value)
        if entropy >= 5.0:
            confidence += 0.2
        elif entropy >= 4.0:
            confidence += 0.1
        
        # Pattern-specific confidence adjustments
        if secret_type in ['aws_access_key', 'google_api_key']:
            confidence += 0.2  # These have very specific patterns
        
        # Character composition confidence
        if self._has_good_char_mix(value):
            confidence += 0.1
        
        # Avoid obvious test values
        if any(test_word in value.lower() for test_word in ['test', 'demo', 'example']):
            confidence -= 0.3
        
        return min(confidence, 1.0)
    
    def _has_good_char_mix(self, string: str) -> bool:
        """Check if string has good character composition for secrets"""
        has_upper = any(c.isupper() for c in string)
        has_lower = any(c.islower() for c in string)
        has_digit = any(c.isdigit() for c in string)
        has_special = any(c in '+/=_-' for c in string)
        
        return sum([has_upper, has_lower, has_digit, has_special]) >= 3
    
    def _is_placeholder(self, value: str) -> bool:
        """Check if value is likely a placeholder"""
        value_lower = value.lower()
        
        # Check against known placeholders
        if value_lower in self.placeholder_values:
            return True
        
        # Check against false positive patterns
        for pattern in self.false_positive_patterns:
            if pattern.match(value):
                return True
        
        # Check for repeated characters (like "aaaaaaa")
        if len(set(value)) <= 2 and len(value) > 5:
            return True
        
        # Check for sequential patterns
        if self._is_sequential(value):
            return True
        
        return False
    
    def _is_sequential(self, string: str) -> bool:
        """Check if string contains sequential patterns"""
        if len(string) < 4:
            return False
        
        # Check for alphabetical sequences
        for i in range(len(string) - 3):
            if (ord(string[i+1]) == ord(string[i]) + 1 and
                ord(string[i+2]) == ord(string[i]) + 2 and
                ord(string[i+3]) == ord(string[i]) + 3):
                return True
        
        # Check for numerical sequences
        try:
            for i in range(len(string) - 3):
                if (string[i].isdigit() and string[i+1].isdigit() and 
                    string[i+2].isdigit() and string[i+3].isdigit()):
                    if (int(string[i+1]) == int(string[i]) + 1 and
                        int(string[i+2]) == int(string[i]) + 2 and
                        int(string[i+3]) == int(string[i]) + 3):
                        return True
        except ValueError:
            pass
        
        return False
    
    def _filter_false_positives(self):
        """Filter out likely false positives"""
        print("[+] Filtering false positives...")
        
        original_count = len(self.secrets)
        
        # Remove obvious false positives
        filtered_secrets = []
        
        for secret in self.secrets:
            value = secret['value']
            
            # Skip very short values for most types
            if len(value) < 6 and secret['type'] not in ['private_key']:
                continue
            
            # Skip very long values (likely not real secrets)
            if len(value) > 500:
                continue
            
            # Skip low confidence secrets with common patterns
            if (secret['confidence'] < 0.4 and 
                any(pattern in value.lower() for pattern in ['example', 'test', 'demo', 'sample'])):
                continue
            
            # Skip values that are clearly not secrets
            if self._is_obviously_not_secret(value):
                continue
            
            filtered_secrets.append(secret)
        
        self.secrets = filtered_secrets
        
        print(f"    Filtered out {original_count - len(self.secrets)} false positives")
    
    def _is_obviously_not_secret(self, value: str) -> bool:
        """Check if value is obviously not a secret"""
        value_lower = value.lower()
        
        # Common non-secret patterns
        non_secret_patterns = [
            'com.android', 'android.', 'androidx.',
            'application/', 'text/', 'image/',
            'http://schemas', 'www.w3.org',
            'xmlns:', 'utf-8', 'iso-8859'
        ]
        
        for pattern in non_secret_patterns:
            if pattern in value_lower:
                return True
        
        # Check if it's a file path or URL scheme
        if ('/' in value and '.' in value) or value.endswith(('.com', '.org', '.net')):
            return True
        
        # Check if it's a MIME type
        if '/' in value and len(value.split('/')) == 2:
            return True
        
        return False
    
    def _deduplicate_and_rank(self):
        """Remove duplicates and rank secrets by confidence"""
        print("[+] Deduplicating and ranking secrets...")
        
        # Remove exact duplicates
        seen_values = set()
        unique_secrets = []
        
        for secret in self.secrets:
            value_key = f"{secret['value']}:{secret['file']}"
            if value_key not in seen_values:
                seen_values.add(value_key)
                unique_secrets.append(secret)
        
        # Sort by confidence and severity
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
        
        unique_secrets.sort(key=lambda x: (
            severity_order.get(x['severity'], 4),
            -x['confidence'],
            -x['entropy']
        ))
        
        self.secrets = unique_secrets
        
        print(f"    Final count: {len(self.secrets)} unique secrets")
    
    def save_results(self, output_file: str):
        """Save secret findings to file"""
        results = {
            'summary': {
                'total_secrets': len(self.secrets),
                'by_severity': self._get_severity_summary(),
                'by_type': self._get_type_summary(),
                'source_path': str(self.source_path)
            },
            'secrets': self.secrets
        }
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"[+] Results saved to {output_file}")
    
    def _get_severity_summary(self) -> Dict[str, int]:
        """Get summary by severity"""
        summary = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        
        for secret in self.secrets:
            severity = secret.get('severity', 'Low')
            summary[severity] = summary.get(severity, 0) + 1
        
        return summary
    
    def _get_type_summary(self) -> Dict[str, int]:
        """Get summary by type"""
        summary = {}
        
        for secret in self.secrets:
            secret_type = secret.get('type', 'unknown')
            summary[secret_type] = summary.get(secret_type, 0) + 1
        
        return summary
    
    def generate_report(self, output_file: str):
        """Generate human-readable report"""
        with open(output_file, 'w') as f:
            f.write("# Secret Analysis Report\n\n")
            f.write(f"**Source:** {self.source_path}\n")
            f.write(f"**Total Secrets Found:** {len(self.secrets)}\n\n")
            
            # Severity summary
            severity_summary = self._get_severity_summary()
            f.write("## Summary by Severity\n\n")
            for severity, count in severity_summary.items():
                if count > 0:
                    f.write(f"- **{severity}:** {count}\n")
            f.write("\n")
            
            # Type summary
            type_summary = self._get_type_summary()
            f.write("## Summary by Type\n\n")
            for secret_type, count in sorted(type_summary.items()):
                f.write(f"- **{secret_type.replace('_', ' ').title()}:** {count}\n")
            f.write("\n")
            
            # Detailed findings
            f.write("## Detailed Findings\n\n")
            
            current_severity = None
            for secret in self.secrets:
                if secret['severity'] != current_severity:
                    current_severity = secret['severity']
                    f.write(f"### {current_severity} Severity\n\n")
                
                f.write(f"#### {secret['description']}\n")
                f.write(f"- **File:** `{secret['file']}:{secret['line_number']}`\n")
                f.write(f"- **Value:** `{secret['value'][:50]}{'...' if len(secret['value']) > 50 else ''}`\n")
                f.write(f"- **Confidence:** {secret['confidence']:.2f}\n")
                f.write(f"- **Entropy:** {secret['entropy']:.2f}\n")
                f.write(f"- **Context:** `{secret['line_content'][:100]}{'...' if len(secret['line_content']) > 100 else ''}`\n\n")
    
    def get_high_confidence_secrets(self, min_confidence: float = 0.7) -> List[Dict]:
        """Get only high-confidence secrets"""
        return [secret for secret in self.secrets if secret['confidence'] >= min_confidence]
    
    def get_critical_secrets(self) -> List[Dict]:
        """Get only critical severity secrets"""
        return [secret for secret in self.secrets if secret['severity'] == 'Critical']


def main():
    parser = argparse.ArgumentParser(description='Find hardcoded secrets in Android APK source code')
    parser.add_argument('source_path', help='Path to decompiled APK source code')
    parser.add_argument('-o', '--output', help='Output file for results (JSON)')
    parser.add_argument('-r', '--report', help='Output file for human-readable report (Markdown)')
    parser.add_argument('-c', '--confidence', type=float, default=0.0, 
                        help='Minimum confidence threshold (0.0-1.0)')
    parser.add_argument('--high-confidence-only', action='store_true',
                        help='Show only high confidence secrets (0.7+)')
    parser.add_argument('--critical-only', action='store_true',
                        help='Show only critical severity secrets')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.source_path):
        print(f"[-] Source path not found: {args.source_path}")
        return
    
    try:
        finder = SecretFinder(args.source_path)
        secrets = finder.find_secrets()
        
        # Apply filters
        if args.high_confidence_only:
            secrets = finder.get_high_confidence_secrets()
        elif args.critical_only:
            secrets = finder.get_critical_secrets()
        elif args.confidence > 0:
            secrets = [s for s in secrets if s['confidence'] >= args.confidence]
        
        # Save results
        if args.output:
            # Update finder's secrets for saving
            finder.secrets = secrets
            finder.save_results(args.output)
        
        # Generate report
        if args.report:
            finder.secrets = secrets
            finder.generate_report(args.report)
        
        print(f"\n[+] Secret analysis complete!")
        print(f"    Found {len(secrets)} secrets")
        
        # Print summary
        severity_summary = {}
        for secret in secrets:
            severity = secret['severity']
            severity_summary[severity] = severity_summary.get(severity, 0) + 1
        
        if severity_summary:
            print(f"\n[+] Severity breakdown:")
            for severity, count in sorted(severity_summary.items()):
                print(f"    {severity}: {count}")
        
        # Print top findings if verbose
        if args.verbose and secrets:
            print(f"\n[+] Top 5 findings:")
            for i, secret in enumerate(secrets[:5], 1):
                print(f"    {i}. {secret['description']} (Confidence: {secret['confidence']:.2f})")
                print(f"       File: {secret['file']}:{secret['line_number']}")
                print(f"       Value: {secret['value'][:50]}{'...' if len(secret['value']) > 50 else ''}")
        
    except Exception as e:
        print(f"[-] Secret analysis failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()


if __name__ == '__main__':
    main()
