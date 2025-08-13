OWASP Mobile Top 10 Manual Testing Checklist

This comprehensive checklist provides step-by-step manual testing procedures for validating each OWASP Mobile Top 10 vulnerability category.

Pre-Testing Setup

Environment Preparation:
- [ ] Rooted Android device or emulator configured
- [ ] Burp Suite proxy configured (127.0.0.1:8080)
- [ ] Frida server running on device
- [ ] Target application installed
- [ ] Testing documentation ready

Device Configuration:
- [ ] USB debugging enabled
- [ ] Proxy settings configured: adb shell settings put global http_proxy 192.168.1.100:8080
- [ ] CA certificate installed if needed
- [ ] Network connectivity verified

M1: Improper Credential Usage

Static Analysis Checklist:
- [ ] Decompile APK using JADX: jadx -d output/ target.apk
- [ ] Search for hardcoded credentials in source code
- [ ] Check strings.xml for exposed secrets: grep -r "password\|secret\|key" res/values/
- [ ] Analyze SharedPreferences usage patterns
- [ ] Review database schemas for plaintext credentials
- [ ] Check for default/test credentials
- [ ] Verify API key storage methods

Search Patterns to Test:
- [ ] "password" = "
- [ ] "api_key" = "
- [ ] "secret" = "
- [ ] "token" = "
- [ ] Basic authentication strings
- [ ] OAuth client secrets

Dynamic Analysis Checklist:
- [ ] Monitor SharedPreferences writes: frida -U -f com.target.app -l credential_monitor.js
- [ ] Intercept login requests in Burp Suite
- [ ] Check authentication headers for exposed credentials
- [ ] Monitor file system for credential storage
- [ ] Test credential validation logic
- [ ] Verify session management

Manual Testing Steps:
1. [ ] Attempt login with default credentials (admin/admin, test/test)
2. [ ] Check if passwords are stored in plaintext
3. [ ] Verify password complexity requirements
4. [ ] Test account lockout mechanisms
5. [ ] Check for credential transmission over insecure channels
6. [ ] Test password reset functionality
7. [ ] Verify multi-factor authentication implementation

Documentation:
- [ ] Screenshot credential exposure
- [ ] Document storage locations
- [ ] Note transmission methods
- [ ] Record validation failures

M2: Inadequate Supply Chain Security

Static Analysis Checklist:
- [ ] Extract and analyze third-party libraries: unzip target.apk -d extracted/
- [ ] List all JAR files: find extracted/ -name "*.jar"
- [ ] Check library versions in build.gradle or similar
- [ ] Research known vulnerabilities for identified libraries
- [ ] Analyze library permissions and capabilities
- [ ] Check for outdated dependencies

Library Analysis Tools:
- [ ] OWASP Dependency Check: dependency-check --scan ./libs/
- [ ] Snyk scan for vulnerabilities
- [ ] Manual CVE database lookup
- [ ] License compliance verification

Manual Testing Steps:
1. [ ] Identify all third-party components
2. [ ] Check component versions against vulnerability databases
3. [ ] Verify library authenticity and integrity
4. [ ] Test functionality when libraries are removed/replaced
5. [ ] Analyze network behavior of third-party components
6. [ ] Check for unnecessary permissions granted to libraries
7. [ ] Verify update mechanisms for dependencies

Documentation:
- [ ] List all identified libraries and versions
- [ ] Document known vulnerabilities
- [ ] Note unnecessary or suspicious libraries
- [ ] Record licensing issues

M3: Insecure Authentication/Authorization

Static Analysis Checklist:
- [ ] Analyze authentication logic in source code
- [ ] Check JWT implementation: grep -r "JWT\|jsonwebtoken" output/
- [ ] Review session management code
- [ ] Check for authentication bypass conditions
- [ ] Analyze biometric authentication implementation
- [ ] Review OAuth/SSO integration

Dynamic Analysis Checklist:
- [ ] Monitor authentication flows: frida -U -f com.target.app -l auth_monitor.js
- [ ] Intercept and analyze JWT tokens
- [ ] Test session fixation vulnerabilities
- [ ] Monitor authentication state changes
- [ ] Test biometric bypass methods

Manual Testing Steps:
1. [ ] Test authentication bypass techniques
   - [ ] Remove authentication headers
   - [ ] Modify authentication responses
   - [ ] Test with invalid session tokens
   - [ ] Bypass biometric authentication
2. [ ] JWT Security Testing
   - [ ] Check for alg=none vulnerability
   - [ ] Test JWT signature verification
   - [ ] Attempt JWT token manipulation
   - [ ] Test for weak JWT secrets
3. [ ] Session Management Testing
   - [ ] Test session timeout
   - [ ] Check for session fixation
   - [ ] Verify logout functionality
   - [ ] Test concurrent sessions
4. [ ] Multi-Factor Authentication Testing
   - [ ] Bypass MFA requirements
   - [ ] Test MFA token reuse
   - [ ] Verify MFA implementation

Documentation:
- [ ] Document authentication flows
- [ ] Record bypass techniques that work
- [ ] Note JWT vulnerabilities
- [ ] Document session management issues

M4: Insufficient Input/Output Validation

Static Analysis Checklist:
- [ ] Search for SQL query construction: grep -r "SELECT\|INSERT\|UPDATE\|DELETE" output/
- [ ] Check XML/JSON parsing: grep -r "XML\|JSON\|parse" output/
- [ ] Analyze input validation functions
- [ ] Review WebView implementations
- [ ] Check file upload handling
- [ ] Analyze API endpoint implementations

Dynamic Analysis Checklist:
- [ ] Monitor input processing: frida -U -f com.target.app -l input_monitor.js
- [ ] Test SQL injection points
- [ ] Monitor WebView JavaScript execution
- [ ] Track file operations and parsing

Manual Testing Steps:
1. [ ] SQL Injection Testing
   - [ ] Test login forms: ' OR 1=1--
   - [ ] Test search fields: '; DROP TABLE users;--
   - [ ] Test numeric inputs: 1' UNION SELECT * FROM users--
   - [ ] Test blind SQL injection techniques
2. [ ] Cross-Site Scripting (XSS) Testing
   - [ ] Test input fields: <script>alert('XSS')</script>
   - [ ] Test WebView inputs: javascript:alert('XSS')
   - [ ] Test stored XSS in user profiles
3. [ ] Command Injection Testing
   - [ ] Test file upload: ; ls -la
   - [ ] Test URL parameters: | cat /etc/passwd
   - [ ] Test form inputs: `whoami`
4. [ ] File Upload Testing
   - [ ] Upload malicious file types
   - [ ] Test path traversal: ../../../etc/passwd
   - [ ] Verify file size restrictions
   - [ ] Test file content validation
5. [ ] XML/JSON Injection Testing
   - [ ] Test XML External Entity (XXE) attacks
   - [ ] Test JSON injection in API calls
   - [ ] Verify input sanitization

Documentation:
- [ ] Record successful injection attempts
- [ ] Document vulnerable input fields
- [ ] Note lack of input validation
- [ ] Screenshot injection results

M5: Insecure Communication

Static Analysis Checklist:
- [ ] Check network security configuration: cat res/xml/network_security_config.xml
- [ ] Search for HTTP URLs: grep -r "http://" output/
- [ ] Analyze SSL/TLS implementation
- [ ] Check certificate pinning implementation
- [ ] Review cleartext traffic permissions

Dynamic Analysis Checklist:
- [ ] Monitor network traffic: adb shell tcpdump -i any -w capture.pcap
- [ ] Test SSL pinning bypass: frida -U -f com.target.app -l ssl_bypass.js
- [ ] Analyze traffic in Burp Suite
- [ ] Test certificate validation

Manual Testing Steps:
1. [ ] Network Traffic Analysis
   - [ ] Capture all network traffic
   - [ ] Identify unencrypted communications
   - [ ] Check for sensitive data in transit
   - [ ] Verify HTTPS implementation
2. [ ] SSL/TLS Testing
   - [ ] Test with invalid certificates
   - [ ] Test with self-signed certificates
   - [ ] Test with expired certificates
   - [ ] Verify cipher suites used
3. [ ] Certificate Pinning Testing
   - [ ] Test if certificate pinning is implemented
   - [ ] Attempt to bypass certificate pinning
   - [ ] Test with different CA certificates
4. [ ] Protocol Security Testing
   - [ ] Test for downgrade attacks
   - [ ] Verify TLS version support
   - [ ] Check for weak cipher usage

Documentation:
- [ ] Record unencrypted communications
- [ ] Document SSL/TLS configuration issues
- [ ] Note certificate pinning bypass success
- [ ] Screenshot network traffic analysis

M6: Inadequate Privacy Controls

Static Analysis Checklist:
- [ ] Review privacy policy implementation
- [ ] Check data collection permissions
- [ ] Analyze consent mechanisms
- [ ] Review data sharing with third parties
- [ ] Check for tracking implementations

Dynamic Analysis Checklist:
- [ ] Monitor data collection: frida -U -f com.target.app -l privacy_monitor.js
- [ ] Track permission usage
- [ ] Monitor network data transmission
- [ ] Analyze third-party SDK behavior

Manual Testing Steps:
1. [ ] Privacy Policy Compliance
   - [ ] Compare privacy policy to actual behavior
   - [ ] Verify data collection disclosures
   - [ ] Check consent mechanisms
   - [ ] Test opt-out functionality
2. [ ] Data Collection Testing
   - [ ] Identify all data collected
   - [ ] Test with minimal permissions
   - [ ] Verify data necessity
   - [ ] Check data retention practices
3. [ ] User Control Testing
   - [ ] Test data deletion functionality
   - [ ] Verify data export capabilities
   - [ ] Test privacy settings
   - [ ] Check consent withdrawal options
4. [ ] Third-Party Sharing Testing
   - [ ] Monitor data shared with third parties
   - [ ] Test tracking prevention
   - [ ] Verify anonymization techniques

Documentation:
- [ ] Document privacy policy violations
- [ ] Record excessive data collection
- [ ] Note lack of user controls
- [ ] Screenshot privacy settings

M7: Insufficient Binary Protections

Static Analysis Checklist:
- [ ] Check code obfuscation level
- [ ] Search for anti-debugging code: grep -r "debug\|ptrace" output/
- [ ] Analyze root detection mechanisms
- [ ] Check for tamper detection
- [ ] Review string encryption

Dynamic Analysis Checklist:
- [ ] Test anti-debugging bypass: frida -U -f com.target.app -l anti_debug_bypass.js
- [ ] Monitor protection mechanisms
- [ ] Test emulator detection bypass
- [ ] Analyze runtime protections

Manual Testing Steps:
1. [ ] Reverse Engineering Difficulty
   - [ ] Assess code readability after decompilation
   - [ ] Check for string obfuscation
   - [ ] Verify control flow obfuscation
   - [ ] Test symbol stripping effectiveness
2. [ ] Anti-Debugging Testing
   - [ ] Test debugging tool detection
   - [ ] Verify debugger attachment prevention
   - [ ] Test dynamic analysis detection
3. [ ] Anti-Tampering Testing
   - [ ] Modify APK and test detection
   - [ ] Test integrity verification
   - [ ] Verify signature checking
4. [ ] Environment Detection Testing
   - [ ] Test root detection bypass
   - [ ] Test emulator detection bypass
   - [ ] Verify hook detection mechanisms

Documentation:
- [ ] Rate protection effectiveness
- [ ] Document successful bypasses
- [ ] Note missing protections
- [ ] Record detection mechanisms

M8: Security Misconfiguration

Static Analysis Checklist:
- [ ] Analyze AndroidManifest.xml thoroughly
- [ ] Check for debug flags: grep -r "debuggable.*true" AndroidManifest.xml
- [ ] Review exported components
- [ ] Check backup allowances
- [ ] Analyze permission usage

Manual Testing Steps:
1. [ ] Manifest Analysis
   - [ ] Check android:debuggable="true"
   - [ ] Verify android:allowBackup="false"
   - [ ] Review exported activities/services
   - [ ] Check permission declarations
2. [ ] Component Security Testing
   - [ ] Test exported components with Drozer
   - [ ] Verify intent filter security
   - [ ] Test deep link vulnerabilities
   - [ ] Check broadcast receiver security
3. [ ] Build Configuration Testing
   - [ ] Check for debug builds in production
   - [ ] Verify signing certificate
   - [ ] Check for test certificates
   - [ ] Analyze build flags
4. [ ] Server Configuration Testing
   - [ ] Test API security headers
   - [ ] Check error message disclosure
   - [ ] Verify CORS configuration
   - [ ] Test endpoint security

Documentation:
- [ ] List all misconfigurations found
- [ ] Document exported components
- [ ] Note debug mode issues
- [ ] Record server-side issues

M9: Insecure Data Storage

Static Analysis Checklist:
- [ ] Search for external storage usage: grep -r "getExternalStorageDirectory" output/
- [ ] Analyze database implementations
- [ ] Check SharedPreferences usage
- [ ] Review file creation patterns
- [ ] Check logging implementations

Dynamic Analysis Checklist:
- [ ] Monitor file operations: frida -U -f com.target.app -l file_monitor.js
- [ ] Track database operations
- [ ] Monitor SharedPreferences
- [ ] Analyze backup files

Manual Testing Steps:
1. [ ] File System Analysis
   - [ ] Extract app data: adb backup com.target.app
   - [ ] Analyze internal storage: adb shell run-as com.target.app
   - [ ] Check external storage: adb shell ls -la /sdcard/Android/data/com.target.app/
   - [ ] Review log files: adb logcat | grep com.target.app
2. [ ] Database Security Testing
   - [ ] Extract databases: find . -name "*.db" -o -name "*.sqlite"
   - [ ] Analyze database schemas: sqlite3 database.db .schema
   - [ ] Check for encrypted databases
   - [ ] Verify access controls
3. [ ] SharedPreferences Testing
   - [ ] Extract preferences: cat shared_prefs/*.xml
   - [ ] Check for sensitive data storage
   - [ ] Verify encryption usage
4. [ ] Backup Testing
   - [ ] Test ADB backup functionality
   - [ ] Analyze backup contents
   - [ ] Check backup encryption

Documentation:
- [ ] Document sensitive data found
- [ ] Record storage locations
- [ ] Note encryption usage
- [ ] Screenshot file system analysis

M10: Insufficient Cryptography

Static Analysis Checklist:
- [ ] Search for weak algorithms: grep -r "MD5\|SHA1\|DES\|RC4" output/
- [ ] Analyze key management: grep -r "SecretKey\|encrypt\|decrypt" output/
- [ ] Check random number generation
- [ ] Review cryptographic implementations

Dynamic Analysis Checklist:
- [ ] Monitor crypto operations: frida -U -f com.target.app -l crypto_monitor.js
- [ ] Intercept encryption keys
- [ ] Analyze key derivation
- [ ] Test cryptographic strength

Manual Testing Steps:
1. [ ] Algorithm Assessment
   - [ ] Identify all cryptographic algorithms used
   - [ ] Check for deprecated algorithms
   - [ ] Verify algorithm implementations
   - [ ] Test key lengths
2. [ ] Key Management Testing
   - [ ] Analyze key generation
   - [ ] Check key storage methods
   - [ ] Test key rotation mechanisms
   - [ ] Verify key derivation functions
3. [ ] Implementation Testing
   - [ ] Test for hardcoded keys
   - [ ] Verify initialization vectors
   - [ ] Check for weak seeds
   - [ ] Test cryptographic modes
4. [ ] Strength Testing
   - [ ] Analyze entropy sources
   - [ ] Test random number generation
   - [ ] Verify cryptographic standards compliance

Documentation:
- [ ] List all cryptographic algorithms
- [ ] Document weak implementations
- [ ] Record key management issues
- [ ] Note compliance failures

Post-Testing Activities

Report Generation:
- [ ] Compile all findings by OWASP category
- [ ] Assign severity ratings (Critical/High/Medium/Low)
- [ ] Include proof-of-concept demonstrations
- [ ] Provide remediation recommendations
- [ ] Create executive summary

Quality Assurance:
- [ ] Verify all findings with multiple methods
- [ ] Cross-reference static and dynamic results
- [ ] Validate manual testing results
- [ ] Ensure reproducibility of findings

Deliverables:
- [ ] Detailed technical report
- [ ] Executive summary
- [ ] Remediation recommendations
- [ ] Proof-of-concept code/screenshots
- [ ] Retesting plan

This comprehensive checklist ensures thorough manual validation of all OWASP Mobile Top 10 vulnerability categories through systematic testing procedures.
