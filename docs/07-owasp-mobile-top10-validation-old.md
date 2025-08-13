OWASP Mobile Top 10 Vulnerability Validation Guide

This comprehensive guide provides step-by-step validation techniques for OWASP Mobile Top 10 (2024) vulnerabilities using static analysis, dynamic analysis, and manual testing approaches.

Table of Contents (OWASP Mobile Top 10 2024):
- M1: Improper Credential Usage
- M2: Inadequate Supply Chain Security  
- M3: Insecure Authentication/Authorization
- M4: Insufficient Input/Output Validation
- M5: Insecure Communication
- M6: Inadequate Privacy Controls
- M7: Insufficient Binary Protections
- M8: Security Misconfiguration
- M9: Insecure Data Storage
- M10: Insufficient Cryptography

Prerequisites:
- Rooted Android device or emulator
- Android Reverse Engineering Toolkit setup
- OWASP ZAP or Burp Suite
- Frida and Objection installed

M1: Improper Credential Usage

Description:
Mismanagement of credentials including hardcoding sensitive information like API keys, passwords, or certificates directly in the application code, storing credentials insecurely, or improper credential transmission.

Static Analysis Validation:

1. AndroidManifest.xml Analysis
Extract and analyze manifest:
apktool d target.apk -o extracted_apk
cat extracted_apk/AndroidManifest.xml

Check for dangerous permissions:
grep -E "(WRITE_EXTERNAL_STORAGE|READ_SMS|RECEIVE_SMS|SEND_SMS|CALL_PHONE|READ_CONTACTS|ACCESS_FINE_LOCATION|CAMERA|RECORD_AUDIO)" extracted_apk/AndroidManifest.xml

Look for exported components:
grep -A 5 -B 5 'android:exported="true"' extracted_apk/AndroidManifest.xml

Check for debug flags:
grep -E "(debuggable|allowBackup)" extracted_apk/AndroidManifest.xml

2. Source Code Analysis
Decompile with JADX:
jadx -d decompiled_source target.apk

Search for insecure API usage:
grep -r "MODE_WORLD_READABLE\|MODE_WORLD_WRITABLE" decompiled_source/
grep -r "setJavaScriptEnabled(true)" decompiled_source/
grep -r "checkServerTrusted" decompiled_source/

Dynamic Analysis Validation:

1. Runtime Permission Testing
Create Frida script to hook permissions:
frida -U -f com.target.app -l scripts/frida_scripts/permission_monitor.js --no-pause

Permission monitoring script (permission_monitor.js):
Java.perform(function() {
    var ActivityCompat = Java.use("androidx.core.app.ActivityCompat");
    ActivityCompat.checkSelfPermission.implementation = function(context, permission) {
        console.log("[+] Permission check: " + permission);
        return this.checkSelfPermission(context, permission);
    };
    
    var Activity = Java.use("android.app.Activity");
    Activity.requestPermissions.implementation = function(permissions, requestCode) {
        console.log("[+] Requesting permissions: " + permissions);
        return this.requestPermissions(permissions, requestCode);
    };
});

2. Exported Component Testing
Install and setup Drozer:
adb install drozer-agent.apk
drozer console connect

List all exported components:
run app.package.attacksurface com.target.app

Test exported activities:
run app.activity.start --component com.target.app com.target.app.ExportedActivity
run app.activity.start --component com.target.app com.target.app.ExportedActivity --extra string key value

Test exported services:
run app.service.start --component com.target.app com.target.app.ExportedService

Test exported broadcast receivers:
run app.broadcast.send --component com.target.app com.target.app.ExportedReceiver

Test exported content providers:
run app.provider.info -a com.target.app
run app.provider.query content://com.target.app.provider/

3. WebView Security Testing
Hook WebView configurations:
frida -U -f com.target.app -l scripts/frida_scripts/webview_monitor.js --no-pause

WebView monitoring script (webview_monitor.js):
Java.perform(function() {
    var WebSettings = Java.use("android.webkit.WebSettings");
    
    WebSettings.setJavaScriptEnabled.implementation = function(enabled) {
        console.log("[+] JavaScript enabled: " + enabled);
        return this.setJavaScriptEnabled(enabled);
    };
    
    WebSettings.setAllowFileAccess.implementation = function(enabled) {
        console.log("[+] File access enabled: " + enabled);
        return this.setAllowFileAccess(enabled);
    };
    
    WebSettings.setAllowFileAccessFromFileURLs.implementation = function(enabled) {
        console.log("[+] File access from file URLs: " + enabled);
        return this.setAllowFileAccessFromFileURLs(enabled);
    };
});

Manual Testing:

1. Permission Analysis
Check requested permissions in AndroidManifest.xml:
aapt dump permissions target.apk

Compare with actually used permissions in code:
grep -r "checkSelfPermission\|requestPermissions" decompiled_source/

Verify dangerous permissions justification:
- CAMERA: Photo/video functionality
- LOCATION: Maps/location services
- CONTACTS: Contact integration
- SMS: SMS functionality
- PHONE: Call functionality

2. Exported Component Manual Testing
Launch exported activities directly:
adb shell am start -n com.target.app/.ExportedActivity
adb shell am start -n com.target.app/.ExportedActivity -e "key" "value"

Start exported services:
adb shell am startservice -n com.target.app/.ExportedService

Send broadcasts to exported receivers:
adb shell am broadcast -a com.target.action -n com.target.app/.ExportedReceiver

Query exported content providers:
adb shell content query --uri content://com.target.app.provider/table

3. Debug Mode Testing
Check if debugging is enabled:
adb shell pm dump com.target.app | grep "debuggable"

If debugging enabled, attach debugger:
adb shell am set-debug-app -w com.target.app
adb forward tcp:8700 jdwp:$(adb shell ps | grep com.target.app | awk '{print $2}')

4. Backup Testing
Check if backup is allowed:
adb shell pm dump com.target.app | grep "allowBackup"

If backup allowed, test backup extraction:
adb backup -all -f backup.ab
dd if=backup.ab bs=1 skip=24 | python -c "import zlib,sys;sys.stdout.write(zlib.decompress(sys.stdin.read()))" | tar -tv

1. WebView Security Testing
Check WebView implementation in source code
Test JavaScript injection via WebView
Verify SSL certificate validation

2. File Permission Testing
Check for world-readable/writable files:
adb shell run-as com.target.app
find . -perm 444 -o -perm 666 -o -perm 777

Weak Spots to Focus:
- Permission declarations vs actual usage
- WebView configurations
- File storage permissions
- Debug flags in production

M2: Insecure Data Storage

Description:
Insecure data storage vulnerabilities occur when development teams assume that users or malware won't have access to a mobile device's filesystem.

Static Analysis Validation:

1. Database Analysis
Extract databases from APK:
strings target.apk | grep -E "\.db|\.sqlite"

Analyze database schemas in source:
grep -r "CREATE TABLE\|INSERT INTO\|SELECT.*FROM" decompiled_source/

Check for encryption usage:
grep -r "encrypt\|cipher\|AES\|DES" decompiled_source/

2. SharedPreferences Analysis
Find SharedPreferences usage:
grep -r "getSharedPreferences\|PreferenceManager" decompiled_source/
grep -r "putString\|getString\|putInt" decompiled_source/

Check for sensitive data in preferences:
grep -r -E "(password|token|key|secret|credit)" decompiled_source/ | grep -i pref

3. File Storage Analysis
Check for external storage usage:
grep -r "getExternalStorageDirectory\|EXTERNAL_STORAGE" decompiled_source/

Look for internal storage without encryption:
grep -r "openFileOutput\|FileOutputStream" decompiled_source/

Dynamic Analysis Validation:

1. Database Extraction and Analysis
Extract app data directory:
adb backup -f backup.ab com.target.app
dd if=backup.ab bs=24 skip=1 | openssl zlib -d | tar -xvf -

Analyze databases:
find . -name "*.db" -o -name "*.sqlite"
sqlite3 database.db ".tables"
sqlite3 database.db "SELECT * FROM sensitive_table;"

2. SharedPreferences Monitoring
Hook SharedPreferences:
frida -U -f com.target.app -l m2_storage_hook.js --no-pause

Monitor file operations:
frida -U -f com.target.app -l file_monitor.js --no-pause

3. Runtime Data Extraction
adb shell run-as com.target.app
find . -type f -name "*.xml" -o -name "*.db" -o -name "*.log"
cat shared_prefs/*.xml

Manual Testing:

1. Device File System Analysis
Root device and browse app data:
adb shell su
cd /data/data/com.target.app
ls -la
find . -type f -exec file {} \;

2. Backup Analysis
Enable app backup and analyze:
adb backup -f backup.ab com.target.app -shared
python android_backup_extractor.py backup.ab

3. Log Analysis
Monitor system logs for data leakage:
adb logcat | grep com.target.app
adb logcat -s "tag_name"

Weak Spots to Focus:
- Unencrypted SQLite databases
- Plain text SharedPreferences
- Sensitive data in logs
- External storage usage
- Backup configurations

M3: Insecure Communication

Description:
Poor handshaking, incorrect SSL versions, weak negotiation, cleartext communication of sensitive assets, etc.

Static Analysis Validation:

1. Network Configuration Analysis
Check network security config:
find extracted_apk -name "network_security_config.xml"
cat extracted_apk/res/xml/network_security_config.xml

Look for cleartext traffic:
grep -r "usesCleartextTraffic" extracted_apk/AndroidManifest.xml
grep -r "android:usesCleartextTraffic=\"true\"" extracted_apk/

2. SSL/TLS Implementation Analysis
Check for custom TrustManager:
grep -r "TrustManager\|X509TrustManager" decompiled_source/
grep -r "checkServerTrusted" decompiled_source/

Look for SSL pinning bypass:
grep -r "HostnameVerifier" decompiled_source/
grep -r "ALLOW_ALL_HOSTNAME_VERIFIER" decompiled_source/

3. HTTP vs HTTPS Usage
Search for HTTP URLs:
grep -r "http://" decompiled_source/
strings target.apk | grep "http://"

Check for hardcoded URLs:
grep -r -E "https?://[^\s\"']+" decompiled_source/

Dynamic Analysis Validation:

1. Network Traffic Interception
Setup Burp Suite proxy:
adb shell settings put global http_proxy 192.168.1.100:8080

Monitor network traffic:
mitmdump -s intercept_script.py
tcpdump -i wlan0 -w capture.pcap

2. SSL Pinning Testing
Test SSL pinning with Frida:
frida -U -f com.target.app -l ssl_pinning_bypass.js --no-pause

Use Objection for SSL bypass:
objection -g com.target.app explore
android sslpinning disable

3. Certificate Validation Testing
Hook certificate validation:
frida -U -f com.target.app -l cert_validation_hook.js --no-pause

Monitor TLS handshakes:
frida-trace -U -f com.target.app -I "*ssl*" -I "*tls*"

Manual Testing:

1. Proxy Testing
Configure device proxy manually
Test with invalid certificates
Analyze captured traffic in Burp/OWASP ZAP

2. Man-in-the-Middle Testing
Setup fake access point
Capture and analyze unencrypted traffic
Test certificate validation bypass

3. Network Security Analysis
Use Wireshark for deep packet inspection
Analyze TLS versions and cipher suites
Check for certificate pinning implementation

Weak Spots to Focus:
- Missing certificate pinning
- Weak TLS configurations
- Cleartext HTTP traffic
- Custom TrustManager implementations
- Improper hostname verification

M4: Insecure Authentication

Description:
Notoriously, mobile applications often implement authentication schemes that are less secure than web applications.

Static Analysis Validation:

1. Authentication Logic Analysis
Find authentication methods:
grep -r "login\|authenticate\|signin" decompiled_source/
grep -r "password\|credential\|token" decompiled_source/

Check for hardcoded credentials:
grep -r -E "password.*=.*[\"'][^\"']+[\"']" decompiled_source/
grep -r -E "api.*key.*=.*[\"'][^\"']+[\"']" decompiled_source/

2. Session Management Analysis
Look for session tokens:
grep -r "session\|token\|jwt" decompiled_source/
grep -r "Authorization\|Bearer" decompiled_source/

Check token storage:
grep -r "SharedPreferences.*token\|Preferences.*session" decompiled_source/

3. Biometric Authentication Analysis
Find biometric implementations:
grep -r "BiometricPrompt\|FingerprintManager" decompiled_source/
grep -r "authenticate.*fingerprint" decompiled_source/

Dynamic Analysis Validation:

1. Authentication Bypass Testing
Hook authentication methods:
frida -U -f com.target.app -l auth_bypass_hook.js --no-pause

Monitor authentication flow:
frida -U -f com.target.app -l auth_monitor.js --no-pause

2. Session Token Analysis
Capture authentication requests:
burpsuite # Intercept login requests
Extract and analyze JWT tokens:
echo "JWT_TOKEN" | base64 -d

3. Biometric Bypass Testing
Hook biometric authentication:
frida -U -f com.target.app -l biometric_bypass.js --no-pause

Test biometric spoofing:
frida -U -f com.target.app -l fingerprint_spoof.js --no-pause

Manual Testing:

1. Authentication Flow Testing
Test with invalid credentials
Check for SQL injection in login forms
Test session timeout mechanisms

2. Multi-factor Authentication Testing
Test 2FA bypass techniques
Analyze backup authentication methods
Test token replay attacks

3. Social Engineering Testing
Test forgot password mechanisms
Check for username enumeration
Test account lockout policies

Weak Spots to Focus:
- Hardcoded credentials
- Weak session management
- Missing MFA
- Biometric authentication bypass
- Password policies

M5: Insufficient Cryptography

Description:
The code applies cryptography to sensitive information or assets but the cryptography is insufficient in some way.

Static Analysis Validation:

1. Cryptographic Implementation Analysis
Find crypto usage:
grep -r "Cipher\|SecretKey\|KeyGenerator" decompiled_source/
grep -r "encrypt\|decrypt\|hash" decompiled_source/

Check for weak algorithms:
grep -r "DES\|MD5\|SHA1" decompiled_source/
grep -r "ECB\|RC4" decompiled_source/

2. Key Management Analysis
Look for hardcoded keys:
grep -r -E "key.*=.*[\"'][a-zA-Z0-9+/=]{16,}[\"']" decompiled_source/
strings target.apk | grep -E "[a-zA-Z0-9+/=]{32,}"

Check key storage:
grep -r "KeyStore\|AndroidKeyStore" decompiled_source/

3. Random Number Generation Analysis
Find random number usage:
grep -r "Random\|SecureRandom" decompiled_source/
grep -r "Math.random\|new Random()" decompiled_source/

Dynamic Analysis Validation:

1. Cryptographic Operation Monitoring
Hook crypto operations:
frida -U -f com.target.app -l crypto_monitor.js --no-pause

Monitor key usage:
frida-trace -U -f com.target.app -I "*cipher*" -I "*key*"

2. Key Extraction
Extract runtime keys:
frida -U -f com.target.app -l key_extractor.js --no-pause

Dump crypto parameters:
frida -U -f com.target.app -l crypto_dump.js --no-pause

3. Weak Crypto Detection
Test for weak implementations:
frida -U -f com.target.app -l weak_crypto_detector.js --no-pause

Manual Testing:

1. Cryptographic Analysis
Analyze encrypted data patterns
Test for known plaintext attacks
Check for padding oracle vulnerabilities

2. Key Brute-forcing
Test weak key derivation
Attempt dictionary attacks on keys
Analyze key rotation mechanisms

3. Side-channel Analysis
Test for timing attacks
Analyze power consumption patterns
Check for cache-based attacks

Weak Spots to Focus:
- Hardcoded encryption keys
- Weak encryption algorithms
- Improper key management
- Weak random number generation
- Custom crypto implementations

M6: Insecure Authorization

Description:
Insecure authorization vulnerabilities occur when an application fails to properly verify that an authenticated user should be permitted to access a particular resource or perform a particular action.

Static Analysis Validation:

1. Authorization Logic Analysis
Find authorization checks:
grep -r "hasPermission\|isAuthorized\|checkAccess" decompiled_source/
grep -r "role\|permission\|access" decompiled_source/

Check for role-based access:
grep -r "admin\|user\|guest\|role" decompiled_source/

2. API Endpoint Analysis
Find API endpoints:
grep -r -E "http[s]?://[^\s\"']+/api/" decompiled_source/
grep -r "REST\|endpoint\|service" decompiled_source/

Check for authorization headers:
grep -r "Authorization\|Bearer\|X-Auth" decompiled_source/

3. Intent Filter Analysis
Check exported components with filters:
grep -A 10 -B 10 "intent-filter" extracted_apk/AndroidManifest.xml

Dynamic Analysis Validation:

1. Authorization Bypass Testing
Hook authorization methods:
frida -U -f com.target.app -l authz_bypass_hook.js --no-pause

Test privilege escalation:
frida -U -f com.target.app -l privilege_escalation.js --no-pause

2. API Authorization Testing
Intercept API calls:
burpsuite # Capture and modify API requests
Test with different user tokens:
curl -H "Authorization: Bearer VICTIM_TOKEN" https://api.target.com/admin/

3. Intent Hijacking Testing
Test exported activities:
adb shell am start -n com.target.app/.AdminActivity
drozer # Test intent injection

Manual Testing:

1. Horizontal Privilege Escalation
Test accessing other users' data
Modify user IDs in requests
Test IDOR vulnerabilities

2. Vertical Privilege Escalation
Test admin functionality with user account
Check for missing authorization checks
Test role-based access controls

3. Business Logic Testing
Test workflow bypass
Check for race conditions
Test state manipulation

Weak Spots to Focus:
- Missing authorization checks
- Insecure direct object references
- Role-based access control flaws
- Intent hijacking vulnerabilities
- API authorization bypasses

M7: Client Code Quality

Description:
Mobile code quality issues are general code-level implementation problems in the mobile client.

Static Analysis Validation:

1. Code Quality Analysis
Use automated tools:
sonarqube-scanner # For comprehensive code analysis
spotbugs # For Java code analysis
lint # Android-specific linting

Check for common issues:
grep -r "printStackTrace\|System.out.print" decompiled_source/
grep -r "Log.d\|Log.v\|Log.i" decompiled_source/

2. Buffer Overflow Detection
Look for native code vulnerabilities:
find . -name "*.so" -exec strings {} \; | grep -E "strcpy|strcat|sprintf"
objdump -d lib/*.so | grep -E "buffer|overflow"

3. Memory Management Analysis
Check for memory leaks:
grep -r "finalize\|gc\|OutOfMemoryError" decompiled_source/

Dynamic Analysis Validation:

1. Runtime Code Quality Testing
Monitor exceptions and errors:
adb logcat | grep -E "Exception|Error|Crash"

Use memory profilers:
am profile start com.target.app /sdcard/profile.trace
am profile stop com.target.app

2. Native Code Analysis
Hook native functions:
frida -U -f com.target.app -l native_hook.js --no-pause

Test buffer overflows:
frida -U -f com.target.app -l buffer_overflow_test.js --no-pause

Manual Testing:

1. Input Validation Testing
Test with malformed inputs
Check for injection vulnerabilities
Test boundary conditions

2. Error Handling Testing
Trigger error conditions
Check for information disclosure
Test exception handling

3. Performance Testing
Test with large datasets
Check for DoS conditions
Analyze resource consumption

Weak Spots to Focus:
- Poor exception handling
- Memory leaks
- Buffer overflows in native code
- Improper input validation
- Information disclosure through logs

M8: Code Tampering

Description:
Code tampering covers binary patching, local resource modification, method hooking, method swizzling, and dynamic memory modification.

Static Analysis Validation:

1. Anti-tampering Detection Analysis
Check for integrity checks:
grep -r "checksum\|hash\|integrity" decompiled_source/
grep -r "signature\|verify" decompiled_source/

Look for obfuscation:
grep -r "obfuscat\|ProGuard" decompiled_source/

2. Debug Detection Analysis
Find debug detection code:
grep -r "isDebuggerConnected\|Debug" decompiled_source/
grep -r "debuggable\|debug" decompiled_source/

3. Root Detection Analysis
Check for root detection:
grep -r "su\|root\|superuser" decompiled_source/
grep -r "/system/bin/su\|/system/xbin/su" decompiled_source/

Dynamic Analysis Validation:

1. Anti-tampering Bypass Testing
Hook integrity checks:
frida -U -f com.target.app -l integrity_bypass.js --no-pause

Test signature verification bypass:
frida -U -f com.target.app -l signature_bypass.js --no-pause

2. Debug Detection Bypass
Bypass debug detection:
frida -U -f com.target.app -l debug_bypass.js --no-pause

Hook isDebuggerConnected:
Java.use("android.os.Debug").isDebuggerConnected.implementation = function() { return false; }

3. Root Detection Bypass
Bypass root detection:
frida -U -f com.target.app -l root_bypass.js --no-pause

Hide root indicators:
mount --bind /system/bin/cat /system/bin/su

Manual Testing:

1. Code Modification Testing
Modify APK and resign:
apktool d target.apk
# Modify code
apktool b modified_app
jarsigner -keystore debug.keystore modified_app.apk alias_name

2. Runtime Manipulation Testing
Test with Xposed modules
Use Cydia Substrate hooks
Test memory patching

3. Anti-analysis Evasion
Bypass anti-emulator checks
Evade anti-analysis techniques
Test in isolated environments

Weak Spots to Focus:
- Weak integrity verification
- Missing anti-tampering controls
- Ineffective obfuscation
- Poor debug/root detection
- Lack of runtime protection

M9: Reverse Engineering

Description:
This category includes analysis of the final core binary to determine its source code, libraries, algorithms, and other assets.

Static Analysis Validation:

1. Code Obfuscation Analysis
Check obfuscation level:
jadx -d output target.apk
# Analyze readability of decompiled code

Test with different decompilers:
dex2jar target.apk
jd-gui target-dex2jar.jar

2. String Analysis
Extract strings:
strings target.apk | grep -E "(url|password|key|token)"
aapt dump strings target.apk

3. Resource Analysis
Extract resources:
aapt dump resources target.apk
unzip target.apk -d extracted/
find extracted/ -name "*.xml" -exec cat {} \;

Dynamic Analysis Validation:

1. Runtime Analysis Protection Testing
Test anti-debugging:
gdb attach PID
ptrace PTRACE_ATTACH PID

Test with analysis tools:
frida -U com.target.app
objection -g com.target.app explore

2. Memory Dumping Testing
Dump process memory:
gcore PID
/proc/PID/maps

Extract runtime strings:
strings /proc/PID/mem

Manual Testing:

1. Reverse Engineering Workflow
Use multiple analysis tools
Cross-reference findings
Document discovered algorithms

2. Protection Assessment
Test strength of obfuscation
Evaluate anti-analysis measures
Check for packing/encryption

3. Asset Extraction
Extract embedded files
Analyze native libraries
Reverse engineer protocols

Weak Spots to Focus:
- Lack of code obfuscation
- Exposed sensitive algorithms
- Weak anti-analysis protection
- Unprotected intellectual property
- Clear text configurations

M10: Extraneous Functionality

Description:
Often, developers include hidden backdoor functionality or other internal development security controls that are not intended to be released into a production environment.

Static Analysis Validation:

1. Debug Code Detection
Search for debug functionality:
grep -r "debug\|test\|dev" decompiled_source/
grep -r "BuildConfig.DEBUG" decompiled_source/

Look for test endpoints:
grep -r -E "(test|dev|staging|debug).*url" decompiled_source/

2. Backdoor Detection
Find suspicious methods:
grep -r "backdoor\|admin\|secret" decompiled_source/
grep -r "hidden\|internal\|private.*key" decompiled_source/

Check for hardcoded access:
grep -r -E "(master|admin|root).*password" decompiled_source/

3. Unused Code Analysis
Identify dead code:
# Use ProGuard mapping or static analysis tools
grep -r "unused\|deprecated" decompiled_source/

Dynamic Analysis Validation:

1. Hidden Functionality Discovery
Test hidden intents:
drozer console connect
run app.package.info -a com.target.app
run app.activity.info -a com.target.app

Test hidden URLs:
burpsuite # Test for hidden endpoints
dirb http://api.target.com/ wordlist.txt

2. Debug Feature Testing
Trigger debug modes:
adb shell setprop debug.target.app 1
adb shell am start -a android.intent.action.MAIN -c android.intent.category.LAUNCHER -n com.target.app/.DebugActivity

Manual Testing:

1. Feature Discovery
Explore all app functionality
Test different user roles
Check for admin panels

2. Configuration Analysis
Test different build variants
Check staging vs production configs
Analyze feature flags

3. Code Review
Manual code review for suspicious patterns
Check version control history
Analyze unused imports/dependencies

Weak Spots to Focus:
- Debug code in production
- Hidden admin interfaces
- Test/staging endpoints
- Backdoor functionality
- Unused but exploitable code

Automation Scripts

The following Python script automates OWASP Top 10 validation:

python scripts/owasp_validation/owasp_scanner.py target.apk

Frida Scripts for Dynamic Analysis:

M1 - Platform Usage Hook:
frida -U -f com.target.app -l owasp_hooks/m1_platform_usage.js --no-pause

M2 - Data Storage Monitor:
frida -U -f com.target.app -l owasp_hooks/m2_data_storage.js --no-pause

M3 - Communication Monitor:
frida -U -f com.target.app -l owasp_hooks/m3_communication.js --no-pause

Comprehensive Testing Workflow:

1. Static Analysis Phase
Run automated tools on APK
Analyze decompiled source code
Check manifest and resources
Generate static analysis report

2. Dynamic Analysis Phase
Setup monitoring environment
Run app with hooks enabled
Capture network traffic
Test runtime protections

3. Manual Testing Phase
Perform targeted testing
Validate automated findings
Test edge cases
Document vulnerabilities

4. Report Generation
Compile all findings
Prioritize by OWASP severity
Provide remediation guidance
Generate executive summary

This guide provides comprehensive coverage of OWASP Mobile Top 10 validation across all analysis methods, ensuring thorough security assessment of Android applications.