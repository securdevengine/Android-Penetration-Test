#!/usr/bin/env python3

import re
import os
import json
import argparse
from pathlib import Path
from typing import List, Dict, Set, Optional
from urllib.parse import urlparse, urljoin
import xml.etree.ElementTree as ET

class EndpointExtractor:
    def __init__(self, source_path: str):
        self.source_path = Path(source_path)
        self.endpoints = []
        self.base_urls = set()
        self.api_patterns = []
        
        # Regex patterns for different types of endpoints
        self.url_patterns = [
            # Standard HTTP/HTTPS URLs
            re.compile(r'https?://[^\s"\'\)\]},;]+', re.IGNORECASE),
            
            # URL with parameters
            re.compile(r'https?://[^\s"\']+\?[^\s"\']*', re.IGNORECASE),
            
            # API endpoints with placeholders
            re.compile(r'https?://[^\s"\']+/api/[^\s"\']*', re.IGNORECASE),
            
            # Relative API paths
            re.compile(r'["\']/?api/[^"\']*["\']', re.IGNORECASE),
            re.compile(r'["\']/?v\d+/[^"\']*["\']', re.IGNORECASE),
            
            # REST endpoints
            re.compile(r'["\'][^"\']*/(get|post|put|delete|patch)/[^"\']*["\']', re.IGNORECASE),
        ]
        
        # Library-specific patterns
        self.library_patterns = {
            'retrofit': {
                'base_url': re.compile(r'baseUrl\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE),
                'annotations': re.compile(r'@(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s*\(\s*["\']([^"\']*)["\']', re.IGNORECASE),
                'endpoint': re.compile(r'@\w+\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE)
            },
            'okhttp': {
                'url_builder': re.compile(r'url\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE),
                'request_url': re.compile(r'Request\.Builder\(\)\.url\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE)
            },
            'volley': {
                'string_request': re.compile(r'StringRequest\s*\([^,]*,\s*["\']([^"\']+)["\']', re.IGNORECASE),
                'json_request': re.compile(r'JsonObjectRequest\s*\([^,]*,\s*["\']([^"\']+)["\']', re.IGNORECASE)
            }
        }
        
        # Common API patterns
        self.api_keywords = [
            'api', 'rest', 'service', 'endpoint', 'webservice',
            'oauth', 'auth', 'login', 'token', 'refresh'
        ]
    
    def extract_endpoints(self) -> List[Dict]:
        """Extract all API endpoints from the source"""
        print(f"[+] Extracting endpoints from {self.source_path}")
        
        if not self.source_path.exists():
            print(f"[-] Source path does not exist: {self.source_path}")
            return []
        
        # Extract from different sources
        self._extract_from_java_files()
        self._extract_from_xml_files()
        self._extract_from_config_files()
        self._extract_library_specific()
        
        # Post-process endpoints
        self._deduplicate_endpoints()
        self._categorize_endpoints()
        self._enrich_endpoints()
        
        print(f"[+] Found {len(self.endpoints)} unique endpoints")
        return self.endpoints
    
    def _extract_from_java_files(self):
        """Extract endpoints from Java source files"""
        print("[+] Scanning Java files...")
        
        java_files = list(self.source_path.rglob('*.java'))
        print(f"    Found {len(java_files)} Java files")
        
        for java_file in java_files:
            try:
                with open(java_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                # Extract URLs using patterns
                for pattern in self.url_patterns:
                    matches = pattern.finditer(content)
                    for match in matches:
                        url = match.group(0).strip('"\'')
                        self._add_endpoint(url, java_file, 'java_pattern')
                
                # Extract string constants that look like endpoints
                self._extract_string_constants(content, java_file)
                
                # Extract from annotations
                self._extract_annotations(content, java_file)
                
            except Exception as e:
                print(f"[-] Error processing {java_file}: {e}")
    
    def _extract_string_constants(self, content: str, file_path: Path):
        """Extract string constants that might be endpoints"""
        # Find string literals
        string_patterns = [
            re.compile(r'public\s+static\s+final\s+String\s+\w+\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE),
            re.compile(r'private\s+static\s+final\s+String\s+\w+\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE),
            re.compile(r'String\s+\w*[Uu][Rr][Ll]\w*\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE),
            re.compile(r'String\s+\w*[Aa][Pp][Ii]\w*\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE),
        ]
        
        for pattern in string_patterns:
            matches = pattern.finditer(content)
            for match in matches:
                url = match.group(1)
                if self._is_likely_endpoint(url):
                    self._add_endpoint(url, file_path, 'string_constant')
    
    def _extract_annotations(self, content: str, file_path: Path):
        """Extract endpoints from annotations"""
        # Retrofit annotations
        retrofit_pattern = re.compile(r'@(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s*\(\s*["\']([^"\']*)["\']', re.IGNORECASE)
        matches = retrofit_pattern.finditer(content)
        
        for match in matches:
            method = match.group(1).upper()
            path = match.group(2)
            
            self._add_endpoint(path, file_path, 'retrofit_annotation', {
                'http_method': method,
                'is_relative': not path.startswith('http')
            })
    
    def _extract_from_xml_files(self):
        """Extract endpoints from XML files"""
        print("[+] Scanning XML files...")
        
        xml_files = list(self.source_path.rglob('*.xml'))
        print(f"    Found {len(xml_files)} XML files")
        
        for xml_file in xml_files:
            try:
                # Check if it's a network security config
                if 'network_security_config' in xml_file.name:
                    self._extract_from_network_config(xml_file)
                    continue
                
                with open(xml_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                # Extract URLs from XML content
                for pattern in self.url_patterns:
                    matches = pattern.finditer(content)
                    for match in matches:
                        url = match.group(0).strip('"\'')
                        self._add_endpoint(url, xml_file, 'xml_content')
                
            except Exception as e:
                print(f"[-] Error processing {xml_file}: {e}")
    
    def _extract_from_network_config(self, config_file: Path):
        """Extract domains from network security config"""
        try:
            tree = ET.parse(config_file)
            root = tree.getroot()
            
            # Find domain configurations
            for domain_config in root.findall('.//domain-config'):
                for domain in domain_config.findall('.//domain'):
                    domain_name = domain.text
                    if domain_name:
                        # Add as HTTPS endpoint (common for API domains)
                        self._add_endpoint(f"https://{domain_name}", config_file, 'network_config')
                        
        except Exception as e:
            print(f"[-] Error parsing network config {config_file}: {e}")
    
    def _extract_from_config_files(self):
        """Extract endpoints from configuration files"""
        print("[+] Scanning configuration files...")
        
        config_patterns = ['*.properties', '*.json', '*.yaml', '*.yml', '*.conf']
        
        for pattern in config_patterns:
            config_files = list(self.source_path.rglob(pattern))
            
            for config_file in config_files:
                try:
                    with open(config_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                    # Extract URLs from config content
                    for url_pattern in self.url_patterns:
                        matches = url_pattern.finditer(content)
                        for match in matches:
                            url = match.group(0).strip('"\'')
                            self._add_endpoint(url, config_file, 'config_file')
                            
                except Exception as e:
                    continue  # Skip problematic files
    
    def _extract_library_specific(self):
        """Extract endpoints using library-specific patterns"""
        print("[+] Extracting library-specific endpoints...")
        
        java_files = list(self.source_path.rglob('*.java'))
        
        for java_file in java_files:
            try:
                with open(java_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Extract base URLs first
                for library, patterns in self.library_patterns.items():
                    if 'base_url' in patterns:
                        matches = patterns['base_url'].finditer(content)
                        for match in matches:
                            base_url = match.group(1)
                            self.base_urls.add(base_url)
                            self._add_endpoint(base_url, java_file, f'{library}_base_url')
                
                # Extract library-specific endpoints
                self._extract_retrofit_endpoints(content, java_file)
                self._extract_okhttp_endpoints(content, java_file)
                self._extract_volley_endpoints(content, java_file)
                
            except Exception as e:
                continue
    
    def _extract_retrofit_endpoints(self, content: str, file_path: Path):
        """Extract Retrofit-specific endpoints"""
        patterns = self.library_patterns['retrofit']
        
        # Extract annotation-based endpoints
        for pattern_name, pattern in patterns.items():
            if pattern_name == 'annotations':
                matches = pattern.finditer(content)
                for match in matches:
                    method = match.group(1).upper()
                    endpoint = match.group(2)
                    
                    self._add_endpoint(endpoint, file_path, 'retrofit', {
                        'http_method': method,
                        'library': 'retrofit',
                        'is_relative': not endpoint.startswith('http')
                    })
    
    def _extract_okhttp_endpoints(self, content: str, file_path: Path):
        """Extract OkHttp-specific endpoints"""
        patterns = self.library_patterns['okhttp']
        
        for pattern_name, pattern in patterns.items():
            matches = pattern.finditer(content)
            for match in matches:
                url = match.group(1)
                self._add_endpoint(url, file_path, 'okhttp', {
                    'library': 'okhttp',
                    'pattern': pattern_name
                })
    
    def _extract_volley_endpoints(self, content: str, file_path: Path):
        """Extract Volley-specific endpoints"""
        patterns = self.library_patterns['volley']
        
        for pattern_name, pattern in patterns.items():
            matches = pattern.finditer(content)
            for match in matches:
                url = match.group(1)
                self._add_endpoint(url, file_path, 'volley', {
                    'library': 'volley',
                    'request_type': pattern_name
                })
    
    def _is_likely_endpoint(self, text: str) -> bool:
        """Check if text is likely an API endpoint"""
        text_lower = text.lower()
        
        # Must contain API-related keywords or patterns
        api_indicators = [
            'api', 'rest', 'service', 'endpoint',
            '/v1/', '/v2/', '/v3/', '/api/',
            'oauth', 'auth', 'login', 'token'
        ]
        
        # Must be reasonable length
        if len(text) < 5 or len(text) > 200:
            return False
        
        # Must contain at least one API indicator
        if not any(indicator in text_lower for indicator in api_indicators):
            return False
        
        # Must look like a URL or path
        if not (text.startswith('http') or text.startswith('/') or '/' in text):
            return False
        
        return True
    
    def _add_endpoint(self, url: str, file_path: Path, source_type: str, metadata: Dict = None):
        """Add an endpoint to the collection"""
        if not url or len(url.strip()) < 3:
            return
        
        url = url.strip()
        
        # Skip obvious non-endpoints
        skip_patterns = [
            'http://schemas.android.com',
            'http://www.w3.org',
            'https://www.w3.org',
            'http://java.sun.com',
            'http://apache.org'
        ]
        
        if any(pattern in url for pattern in skip_patterns):
            return
        
        endpoint_data = {
            'url': url,
            'source_file': str(file_path.relative_to(self.source_path)) if file_path else 'unknown',
            'source_type': source_type,
            'metadata': metadata or {}
        }
        
        # Add parsed URL information
        if url.startswith('http'):
            try:
                parsed = urlparse(url)
                endpoint_data['parsed'] = {
                    'scheme': parsed.scheme,
                    'domain': parsed.netloc,
                    'path': parsed.path,
                    'query': parsed.query,
                    'fragment': parsed.fragment
                }
            except Exception:
                pass
        
        self.endpoints.append(endpoint_data)
    
    def _deduplicate_endpoints(self):
        """Remove duplicate endpoints"""
        print("[+] Deduplicating endpoints...")
        
        seen_urls = set()
        unique_endpoints = []
        
        for endpoint in self.endpoints:
            url = endpoint['url']
            
            # Normalize URL for comparison
            normalized_url = url.lower().rstrip('/')
            
            if normalized_url not in seen_urls:
                seen_urls.add(normalized_url)
                unique_endpoints.append(endpoint)
        
        original_count = len(self.endpoints)
        self.endpoints = unique_endpoints
        
        print(f"    Removed {original_count - len(self.endpoints)} duplicates")
    
    def _categorize_endpoints(self):
        """Categorize endpoints by type"""
        print("[+] Categorizing endpoints...")
        
        for endpoint in self.endpoints:
            url = endpoint['url'].lower()
            categories = []
            
            # Authentication endpoints
            if any(keyword in url for keyword in ['auth', 'login', 'token', 'oauth', 'signin']):
                categories.append('authentication')
            
            # API versioned endpoints
            if any(version in url for version in ['/v1/', '/v2/', '/v3/', '/api/v']):
                categories.append('versioned_api')
            
            # REST endpoints
            if any(method in url for method in ['/get/', '/post/', '/put/', '/delete/', '/patch/']):
                categories.append('rest')
            
            # Data endpoints
            if any(keyword in url for keyword in ['data', 'json', 'xml', 'feed']):
                categories.append('data')
            
            # User-related endpoints
            if any(keyword in url for keyword in ['user', 'profile', 'account', 'member']):
                categories.append('user')
            
            # File endpoints
            if any(keyword in url for keyword in ['file', 'upload', 'download', 'media', 'image']):
                categories.append('file')
            
            endpoint['categories'] = categories
    
    def _enrich_endpoints(self):
        """Enrich endpoints with additional information"""
        print("[+] Enriching endpoint information...")
        
        for endpoint in self.endpoints:
            url = endpoint['url']
            
            # Determine if it's a complete URL or relative path
            endpoint['is_complete_url'] = url.startswith('http')
            
            # Suggest possible complete URLs for relative paths
            if not endpoint['is_complete_url'] and self.base_urls:
                suggested_urls = []
                for base_url in self.base_urls:
                    try:
                        complete_url = urljoin(base_url.rstrip('/') + '/', url.lstrip('/'))
                        suggested_urls.append(complete_url)
                    except Exception:
                        continue
                
                if suggested_urls:
                    endpoint['suggested_complete_urls'] = suggested_urls
            
            # Extract parameters from URL
            if '?' in url:
                try:
                    parsed = urlparse(url)
                    if parsed.query:
                        params = []
                        for param_pair in parsed.query.split('&'):
                            if '=' in param_pair:
                                key, value = param_pair.split('=', 1)
                                params.append({'key': key, 'value': value})
                            else:
                                params.append({'key': param_pair, 'value': ''})
                        
                        endpoint['parameters'] = params
                except Exception:
                    pass
            
            # Determine security implications
            security_notes = []
            
            if url.startswith('http://'):
                security_notes.append('Uses HTTP (unencrypted)')
            
            if any(keyword in url.lower() for keyword in ['debug', 'test', 'dev']):
                security_notes.append('Appears to be development/debug endpoint')
            
            if any(keyword in url.lower() for keyword in ['admin', 'management', 'config']):
                security_notes.append('Potentially sensitive administrative endpoint')
            
            if security_notes:
                endpoint['security_notes'] = security_notes
    
    def save_results(self, output_file: str):
        """Save extraction results to file"""
        results = {
            'summary': {
                'total_endpoints': len(self.endpoints),
                'base_urls': list(self.base_urls),
                'extraction_date': str(Path.cwd()),
                'source_path': str(self.source_path)
            },
            'endpoints': self.endpoints
        }
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"[+] Results saved to {output_file}")
    
    def generate_report(self, output_file: str):
        """Generate a human-readable report"""
        with open(output_file, 'w') as f:
            f.write("# API Endpoint Extraction Report\n\n")
            f.write(f"**Source:** {self.source_path}\n")
            f.write(f"**Total Endpoints:** {len(self.endpoints)}\n")
            f.write(f"**Base URLs:** {len(self.base_urls)}\n\n")
            
            # Base URLs section
            if self.base_urls:
                f.write("## Base URLs\n\n")
                for base_url in sorted(self.base_urls):
                    f.write(f"- `{base_url}`\n")
                f.write("\n")
            
            # Categorized endpoints
            categories = {}
            for endpoint in self.endpoints:
                for category in endpoint.get('categories', ['uncategorized']):
                    if category not in categories:
                        categories[category] = []
                    categories[category].append(endpoint)
            
            for category, endpoints in categories.items():
                f.write(f"## {category.title()} Endpoints ({len(endpoints)})\n\n")
                
                for endpoint in endpoints[:20]:  # Limit to 20 per category
                    f.write(f"- `{endpoint['url']}`\n")
                    
                    if endpoint.get('metadata', {}).get('http_method'):
                        f.write(f"  - Method: {endpoint['metadata']['http_method']}\n")
                    
                    if endpoint.get('security_notes'):
                        f.write(f"  - Security: {', '.join(endpoint['security_notes'])}\n")
                    
                    f.write(f"  - Source: {endpoint['source_file']}\n")
                
                if len(endpoints) > 20:
                    f.write(f"  ... and {len(endpoints) - 20} more\n")
                
                f.write("\n")


def main():
    parser = argparse.ArgumentParser(description='Extract API endpoints from Android APK source code')
    parser.add_argument('source_path', help='Path to decompiled APK source code')
    parser.add_argument('-o', '--output', help='Output file for results (JSON)')
    parser.add_argument('-r', '--report', help='Output file for human-readable report (Markdown)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.source_path):
        print(f"[-] Source path not found: {args.source_path}")
        return
    
    try:
        extractor = EndpointExtractor(args.source_path)
        endpoints = extractor.extract_endpoints()
        
        # Save results
        if args.output:
            extractor.save_results(args.output)
        else:
            # Default output file
            output_file = f"{Path(args.source_path).name}_endpoints.json"
            extractor.save_results(output_file)
        
        # Generate report
        if args.report:
            extractor.generate_report(args.report)
        else:
            # Default report file
            report_file = f"{Path(args.source_path).name}_endpoints_report.md"
            extractor.generate_report(report_file)
        
        print(f"\n[+] Extraction complete!")
        print(f"    Found {len(endpoints)} endpoints")
        print(f"    Found {len(extractor.base_urls)} base URLs")
        
        # Print summary of categories
        categories = {}
        for endpoint in endpoints:
            for category in endpoint.get('categories', ['uncategorized']):
                categories[category] = categories.get(category, 0) + 1
        
        if categories:
            print(f"\n[+] Endpoint categories:")
            for category, count in sorted(categories.items()):
                print(f"    {category}: {count}")
        
    except Exception as e:
        print(f"[-] Extraction failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()


if __name__ == '__main__':
    main()
