# 🔬 Dynamic Analysis Guide

This comprehensive guide covers dynamic analysis techniques for Android applications, including runtime manipulation, traffic interception, and behavioral analysis.

## 🎯 Objectives

- Perform runtime instrumentation with Frida
- Intercept and analyze network traffic
- Bypass security controls (SSL pinning, root detection)
- Monitor file system and database operations
- Automate dynamic testing with Python scripts

## 🛠️ Tools Overview

### Runtime Instrumentation
- **Frida** - Dynamic code instrumentation framework
- **Objection** - Runtime mobile exploration toolkit
- **Xposed Framework** - Android hooking framework (older devices)

### Network Analysis
- **Burp Suite** - Web application security testing
- **OWASP ZAP** - Open source security proxy
- **Wireshark** - Network protocol analyzer
- **mitmproxy** - Interactive HTTPS proxy

### Specialized Tools
- **Drozer** - Android security assessment framework
- **r2frida** - Radare2 + Frida integration
- **House** - Runtime mobile application analysis platform

## 🚀 Phase 1: Environment Preparation

### 1.1 Start Frida Server
```bash
# Push Frida server to device
adb push frida-server-16.1.4-android-arm64 /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server

# Start Frida server (choose method based on device)
# Method 1: Direct execution
adb shell "/data/local/tmp/frida-server &"

# Method 2: With process hiding (avoid detection)
adb shell "mv /data/local/tmp/frida-server /data/local/tmp/android_service"
adb shell "/data/local/tmp/android_service &"

# Verify connection
frida-ps -U
```

### 1.2 Configure Network Proxy
```bash
# Set device proxy for Burp Suite
adb shell settings put global http_proxy 192.168.1.100:8080

# Alternative: Use iptables for transparent proxy
adb shell iptables -t nat -A OUTPUT -p tcp --dport 80 -j DNAT --to-destination 192.168.1.100:8080
adb shell iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination 192.168.1.100:8080
```

### 1.3 Install Target Application
```bash
# Install APK
adb install target.apk

# Grant runtime permissions
adb shell pm grant com.target.app android.permission.CAMERA
adb shell pm grant com.target.app android.permission.READ_EXTERNAL_STORAGE

# Start application
adb shell am start -n com.target.app/.MainActivity
```

## 🔧 Phase 2: Frida Hooking Techniques

### 2.1 Basic Application Hooking

#### Hook Application Startup
```javascript
// frida_scripts/general/app_startup_hook.js
Java.perform(() => {
    console.log("[+] Frida attached to application");
    
    // Hook Application class
    const Application = Java.use("android.app.Application");
    Application.onCreate.implementation = function() {
        console.log("[+] Application.onCreate() called");
        console.log("[+] Package: " + this.getPackageName());
        console.log("[+] Data Dir: " + this.getFilesDir());
        
        this.onCreate();
    };
    
    // Hook Activity launches
    const Activity = Java.use("android.app.Activity");
    Activity.onCreate.implementation = function(bundle) {
        console.log("[+] Activity started: " + this.getClass().getName());
        this.onCreate(bundle);
    };
});
```

#### Monitor Method Calls
```javascript
// frida_scripts/general/method_tracer.js
Java.perform(() => {
    const targetClass = "com.target.app.CryptoManager";
    const CryptoManager = Java.use(targetClass);
    
    // Hook all methods of a class
    const methods = CryptoManager.class.getDeclaredMethods();
    methods.forEach(method => {
        const methodName = method.getName();
        console.log("[+] Hooking method: " + methodName);
        
        CryptoManager[methodName].implementation = function() {
            console.log("[+] Called: " + targetClass + "." + methodName);
            console.log("[+] Arguments: " + JSON.stringify(arguments));
            
            const result = this[methodName].apply(this, arguments);
            console.log("[+] Return value: " + result);
            
            return result;
        };
    });
});
```

### 2.2 Advanced Hooking Patterns

#### Hook with Stack Trace
```javascript
// frida_scripts/general/stack_tracer.js
Java.perform(() => {
    const Log = Java.use("android.util.Log");
    Log.d.overload('java.lang.String', 'java.lang.String').implementation = function(tag, msg) {
        if (tag.includes("AUTH") || msg.includes("token")) {
            console.log("[+] Sensitive log detected:");
            console.log("    Tag: " + tag);
            console.log("    Message: " + msg);
            console.log("    Stack trace:");
            
            const Exception = Java.use("java.lang.Exception");
            const stack = Exception.$new().getStackTrace();
            for (let i = 0; i < stack.length; i++) {
                console.log("      " + stack[i].toString());
            }
        }
        
        return this.d(tag, msg);
    };
});
```

#### Hook Native Functions
```javascript
// frida_scripts/general/native_hook.js
Interceptor.attach(Module.findExportByName("libnative.so", "encrypt_data"), {
    onEnter: function(args) {
        console.log("[+] encrypt_data() called");
        console.log("    arg0 (data): " + Memory.readUtf8String(args[0]));
        console.log("    arg1 (key): " + Memory.readUtf8String(args[1]));
        
        // Store arguments for onLeave
        this.data = Memory.readUtf8String(args[0]);
        this.key = Memory.readUtf8String(args[1]);
    },
    
    onLeave: function(retval) {
        console.log("[+] encrypt_data() return:");
        console.log("    Input: " + this.data);
        console.log("    Key: " + this.key);
        console.log("    Encrypted: " + Memory.readUtf8String(retval));
        
        // Optionally modify return value
        // retval.replace(Memory.allocUtf8String("fake_encrypted_data"));
    }
});
```

### 2.3 Runtime Data Manipulation

#### Modify Method Arguments
```javascript
// frida_scripts/general/argument_modifier.js
Java.perform(() => {
    const AuthManager = Java.use("com.target.app.AuthManager");
    
    AuthManager.validateUser.implementation = function(username, password) {
        console.log("[+] Original credentials:");
        console.log("    Username: " + username);
        console.log("    Password: " + password);
        
        // Modify arguments
        const modifiedUsername = "admin";
        const modifiedPassword = "password123";
        
        console.log("[+] Modified credentials:");
        console.log("    Username: " + modifiedUsername);
        console.log("    Password: " + modifiedPassword);
        
        return this.validateUser(modifiedUsername, modifiedPassword);
    };
});
```

#### Bypass Security Checks
```javascript
// frida_scripts/general/security_bypass.js
Java.perform(() => {
    // Bypass signature verification
    const PackageManager = Java.use("android.content.pm.PackageManager");
    PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(packageName, flags) {
        console.log("[+] Package info request: " + packageName);
        const result = this.getPackageInfo(packageName, flags);
        
        if (packageName === "com.target.app") {
            console.log("[+] Spoofing package signature");
            // Modify signature if needed
        }
        
        return result;
    };
    
    // Bypass license checks
    const LicenseChecker = Java.use("com.target.app.LicenseChecker");
    LicenseChecker.isValidLicense.implementation = function() {
        console.log("[+] License check bypassed - returning true");
        return true;
    };
});
```

## 🌐 Phase 3: Network Traffic Analysis

### 3.1 SSL Certificate Pinning Bypass

#### Universal SSL Bypass
```javascript
// frida_scripts/ssl_bypass/universal_ssl_bypass.js
Java.perform(() => {
    console.log("[+] Loading universal SSL bypass...");
    
    // Bypass TrustManager
    const X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    const HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
    const SSLContext = Java.use('javax.net.ssl.SSLContext');
    const TrustManager = Java.use('javax.net.ssl.TrustManager');
    
    // Create custom TrustManager that trusts all certificates
    const TrustAllManager = Java.registerClass({
        name: 'TrustAllManager',
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(certs, authType) {
                console.log('[+] checkClientTrusted bypassed');
            },
            checkServerTrusted: function(certs, authType) {
                console.log('[+] checkServerTrusted bypassed');
            },
            getAcceptedIssuers: function() {
                console.log('[+] getAcceptedIssuers bypassed');
                return [];
            }
        }
    });
    
    // Create custom HostnameVerifier
    const TrustAllHostnameVerifier = Java.registerClass({
        name: 'TrustAllHostnameVerifier',
        implements: [HostnameVerifier],
        methods: {
            verify: function(hostname, session) {
                console.log('[+] HostnameVerifier bypassed for: ' + hostname);
                return true;
            }
        }
    });
    
    // Hook SSLContext.init
    SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function(keyManagers, trustManagers, secureRandom) {
        console.log('[+] SSLContext.init() bypassed');
        const trustAllManager = TrustAllManager.$new();
        return this.init(keyManagers, [trustAllManager], secureRandom);
    };
});
```

#### OkHttp Specific Bypass
```javascript
// frida_scripts/ssl_bypass/okhttp_bypass.js
Java.perform(() => {
    console.log("[+] OkHttp SSL pinning bypass loaded");
    
    try {
        // OkHttp 3.x
        const CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            console.log('[+] OkHttp CertificatePinner.check() bypassed for: ' + hostname);
            return;
        };
        
        // Alternative: Replace the pins
        CertificatePinner.findMatchingPins.implementation = function(hostname) {
            console.log('[+] OkHttp findMatchingPins() bypassed for: ' + hostname);
            return Java.use('java.util.Collections').emptyList();
        };
        
    } catch (err) {
        console.log('[-] OkHttp 3.x not found');
    }
    
    try {
        // OkHttp 4.x (OkHttp uses kotlin, different approach needed)
        const CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner['check$okhttp'].implementation = function(hostname, peerCertificates) {
            console.log('[+] OkHttp4 CertificatePinner.check() bypassed for: ' + hostname);
            return;
        };
    } catch (err) {
        console.log('[-] OkHttp 4.x not found');
    }
});
```

### 3.2 Network Traffic Monitoring

#### HTTP/HTTPS Request Logging
```javascript
// frida_scripts/general/network_tracer.js
Java.perform(() => {
    console.log("[+] Network traffic monitoring started");
    
    // Hook URL connections
    const URL = Java.use('java.net.URL');
    URL.openConnection.overload().implementation = function() {
        const connection = this.openConnection();
        console.log('[+] URL Connection: ' + this.toString());
        return connection;
    };
    
    // Hook HttpURLConnection
    const HttpURLConnection = Java.use('java.net.HttpURLConnection');
    HttpURLConnection.getResponseCode.implementation = function() {
        const responseCode = this.getResponseCode();
        console.log('[+] HTTP Response: ' + responseCode + ' for ' + this.getURL());
        return responseCode;
    };
    
    // Hook OkHttp requests
    try {
        const Request = Java.use('okhttp3.Request');
        const RequestBuilder = Java.use('okhttp3.Request$Builder');
        
        RequestBuilder.build.implementation = function() {
            const request = this.build();
            console.log('[+] OkHttp Request:');
            console.log('    URL: ' + request.url());
            console.log('    Method: ' + request.method());
            console.log('    Headers: ' + request.headers());
            
            return request;
        };
    } catch (err) {
        console.log('[-] OkHttp not found');
    }
});
```

### 3.3 Burp Suite Integration

#### Configure Burp for Android
```bash
# Generate Burp CA certificate
# Burp → Proxy → Options → Import/Export CA certificate → Export Certificate in DER format

# Convert to Android format
openssl x509 -inform DER -in cacert.der -out cacert.pem
HASH=$(openssl x509 -inform PEM -subject_hash_old -in cacert.pem | head -1)
mv cacert.pem ${HASH}.0

# Install on device
adb push ${HASH}.0 /system/etc/security/cacerts/
adb shell chmod 644 /system/etc/security/cacerts/${HASH}.0
adb reboot
```

#### Automated Burp API Usage
```python
# scripts/dynamic_analysis/burp_automation.py
import requests
import json
import base64

class BurpAPIClient:
    def __init__(self, host='127.0.0.1', port=8080):
        self.base_url = f'http://{host}:{port}'
        self.session = requests.Session()
    
    def start_scan(self, target_url):
        """Start active scan on target URL"""
        data = {
            'url': target_url,
            'scope': 'all'
        }
        response = self.session.post(f'{self.base_url}/burp/scanner/scans/active', json=data)
        return response.json()
    
    def get_scan_results(self, scan_id):
        """Get scan results for specific scan ID"""
        response = self.session.get(f'{self.base_url}/burp/scanner/scans/{scan_id}')
        return response.json()
    
    def export_site_map(self, target_url):
        """Export site map for target URL"""
        data = {'urlPrefix': target_url}
        response = self.session.get(f'{self.base_url}/burp/target/sitemap', params=data)
        return response.json()

# Usage example
burp = BurpAPIClient()
scan_result = burp.start_scan('https://api.target.com')
print(f"Scan started with ID: {scan_result['scanId']}")
```

## 📱 Phase 4: Runtime Security Bypass

### 4.1 Root Detection Bypass

#### Comprehensive Root Bypass
```javascript
// frida_scripts/anti_debug/root_bypass.js
Java.perform(() => {
    console.log("[+] Root detection bypass loaded");
    
    // Bypass common root detection methods
    const checks = [
        // Su binary checks
        { class: 'java.io.File', method: 'exists' },
        { class: 'java.io.File', method: 'canExecute' },
        
        // Package manager checks
        { class: 'android.content.pm.PackageManager', method: 'getPackageInfo' },
        { class: 'android.content.pm.PackageManager', method: 'getInstalledPackages' },
        
        // System property checks
        { class: 'java.lang.System', method: 'getProperty' },
        { class: 'android.os.SystemProperties', method: 'get' },
        
        // Native checks
        { class: 'java.lang.Runtime', method: 'exec' }
    ];
    
    checks.forEach(check => {
        try {
            const targetClass = Java.use(check.class);
            const originalMethod = targetClass[check.method];
            
            if (originalMethod.overloads) {
                originalMethod.overloads.forEach(overload => {
                    overload.implementation = function() {
                        const args = Array.prototype.slice.call(arguments);
                        const result = originalMethod.apply(this, arguments);
                        
                        // Check for root-related arguments
                        const argStr = args.join(' ').toLowerCase();
                        if (argStr.includes('su') || argStr.includes('root') || 
                            argStr.includes('magisk') || argStr.includes('busybox')) {
                            console.log(`[+] Root check bypassed: ${check.class}.${check.method}(${argStr})`);
                            
                            // Return spoofed results
                            if (check.method === 'exists' || check.method === 'canExecute') {
                                return false;
                            } else if (check.method === 'getPackageInfo') {
                                const PackageManager = Java.use('android.content.pm.PackageManager');
                                const NameNotFoundException = Java.use('android.content.pm.PackageManager$NameNotFoundException');
                                throw NameNotFoundException.$new();
                            }
                        }
                        
                        return result;
                    };
                });
            }
        } catch (err) {
            console.log(`[-] Could not hook ${check.class}.${check.method}: ${err}`);
        }
    });
    
    // Bypass specific root detection frameworks
    bypassRootBeer();
    bypassSafetyNet();
});

function bypassRootBeer() {
    try {
        const RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
        RootBeer.isRooted.implementation = function() {
            console.log('[+] RootBeer.isRooted() bypassed');
            return false;
        };
    } catch (err) {
        console.log('[-] RootBeer not found');
    }
}

function bypassSafetyNet() {
    try {
        const SafetyNet = Java.use('com.google.android.gms.safetynet.SafetyNet');
        SafetyNet.getClient.implementation = function() {
            console.log('[+] SafetyNet bypassed');
            return null;
        };
    } catch (err) {
        console.log('[-] SafetyNet not found');
    }
}
```

### 4.2 Anti-Debugging Bypass

#### JDWP Detection Bypass
```javascript
// frida_scripts/anti_debug/jdwp_bypass.js
Java.perform(() => {
    console.log("[+] JDWP detection bypass loaded");
    
    // Bypass Debug.isDebuggerConnected()
    const Debug = Java.use("android.os.Debug");
    Debug.isDebuggerConnected.implementation = function() {
        console.log("[+] Debug.isDebuggerConnected() bypassed");
        return false;
    };
    
    // Bypass ApplicationInfo.FLAG_DEBUGGABLE check
    const ApplicationInfo = Java.use("android.content.pm.ApplicationInfo");
    const Context = Java.use("android.content.Context");
    
    Context.getApplicationInfo.implementation = function() {
        const appInfo = this.getApplicationInfo();
        const FLAG_DEBUGGABLE = 2;
        
        if (appInfo.flags.value & FLAG_DEBUGGABLE) {
            console.log("[+] Removing FLAG_DEBUGGABLE from ApplicationInfo");
            appInfo.flags.value = appInfo.flags.value & ~FLAG_DEBUGGABLE;
        }
        
        return appInfo;
    };
});
```

#### TracerPid Detection Bypass
```javascript
// frida_scripts/anti_debug/tracerpid_bypass.js
const openPtr = Module.getExportByName("libc.so", "open");
const open = new NativeFunction(openPtr, "int", ["pointer", "int"]);

const readPtr = Module.getExportByName("libc.so", "read");
const read = new NativeFunction(readPtr, "int", ["int", "pointer", "int"]);

Interceptor.replace(openPtr, new NativeCallback(function(pathPtr, flags) {
    const path = pathPtr.readCString();
    
    if (path === "/proc/self/status" || path === "/proc/self/stat") {
        console.log("[+] Blocking access to " + path);
        return -1; // Return error
    }
    
    return open(pathPtr, flags);
}, "int", ["pointer", "int"]));

// Alternative: Spoof the content
Interceptor.replace(readPtr, new NativeCallback(function(fd, bufPtr, count) {
    const result = read(fd, bufPtr, count);
    
    if (result > 0) {
        const content = bufPtr.readUtf8String(result);
        if (content.includes("TracerPid:") && !content.includes("TracerPid:\t0")) {
            console.log("[+] Spoofing TracerPid in /proc/self/status");
            const spoofed = content.replace(/TracerPid:\s*\d+/, "TracerPid:\t0");
            bufPtr.writeUtf8String(spoofed);
            return spoofed.length;
        }
    }
    
    return result;
}, "int", ["int", "pointer", "int"]));
```

## 📊 Phase 5: Data Collection and Monitoring

### 5.1 File System Monitoring

#### Comprehensive File Monitor
```javascript
// frida_scripts/general/file_monitor.js
Java.perform(() => {
    console.log("[+] File system monitoring started");
    
    // Monitor file operations
    const File = Java.use("java.io.File");
    const FileInputStream = Java.use("java.io.FileInputStream");
    const FileOutputStream = Java.use("java.io.FileOutputStream");
    
    // Hook file creation/access
    File.$init.overload("java.lang.String").implementation = function(path) {
        if (path.includes("/data/data/") || path.includes("/sdcard/") || 
            path.includes("cache") || path.includes("database")) {
            console.log("[+] File access: " + path);
            
            // Log stack trace for sensitive paths
            if (path.includes("database") || path.includes("key")) {
                const Exception = Java.use("java.lang.Exception");
                const stack = Exception.$new().getStackTrace();
                console.log("    Stack trace:");
                for (let i = 0; i < Math.min(5, stack.length); i++) {
                    console.log("      " + stack[i].toString());
                }
            }
        }
        
        return this.$init(path);
    };
    
    // Monitor file reads
    FileInputStream.$init.overload("java.io.File").implementation = function(file) {
        const path = file.getAbsolutePath();
        console.log("[+] File read: " + path);
        return this.$init(file);
    };
    
    // Monitor file writes
    FileOutputStream.$init.overload("java.io.File").implementation = function(file) {
        const path = file.getAbsolutePath();
        console.log("[+] File write: " + path);
        return this.$init(file);
    };
});
```

### 5.2 Database Monitoring

#### SQLite Operations Monitor
```javascript
// frida_scripts/general/database_monitor.js
Java.perform(() => {
    console.log("[+] Database monitoring started");
    
    // Hook SQLiteDatabase operations
    const SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
    
    // Monitor raw SQL queries
    SQLiteDatabase.rawQuery.overload("java.lang.String", "[Ljava.lang.String;").implementation = function(sql, selectionArgs) {
        console.log("[+] SQL Query: " + sql);
        if (selectionArgs) {
            console.log("    Args: " + selectionArgs.join(", "));
        }
        
        const result = this.rawQuery(sql, selectionArgs);
        return result;
    };
    
    // Monitor execSQL
    SQLiteDatabase.execSQL.overload("java.lang.String").implementation = function(sql) {
        console.log("[+] SQL Exec: " + sql);
        return this.execSQL(sql);
    };
    
    // Monitor insert operations
    SQLiteDatabase.insert.implementation = function(table, nullColumnHack, values) {
        console.log("[+] SQL Insert into table: " + table);
        console.log("    Values: " + values.toString());
        return this.insert(table, nullColumnHack, values);
    };
    
    // Monitor update operations
    SQLiteDatabase.update.overload("java.lang.String", "android.content.ContentValues", "java.lang.String", "[Ljava.lang.String;").implementation = function(table, values, whereClause, whereArgs) {
        console.log("[+] SQL Update table: " + table);
        console.log("    Values: " + values.toString());
        console.log("    Where: " + whereClause);
        return this.update(table, values, whereClause, whereArgs);
    };
});
```

### 5.3 Automated Data Collection

#### Python Automation Script
```python
# scripts/dynamic_analysis/frida_automation.py
import frida
import sys
import time
import json
from threading import Thread

class FridaAutomation:
    def __init__(self, package_name):
        self.package_name = package_name
        self.device = frida.get_usb_device()
        self.session = None
        self.scripts = []
        self.data_collected = {
            'network_requests': [],
            'file_operations': [],
            'crypto_operations': [],
            'api_calls': []
        }
    
    def load_script(self, script_path, script_name=None):
        """Load and attach Frida script"""
        try:
            with open(script_path, 'r') as f:
                script_code = f.read()
            
            script = self.session.create_script(script_code)
            script.on('message', self.on_message)
            script.load()
            
            self.scripts.append({
                'name': script_name or script_path,
                'script': script
            })
            
            print(f"[+] Loaded script: {script_name or script_path}")
            
        except Exception as e:
            print(f"[-] Failed to load script {script_path}: {e}")
    
    def on_message(self, message, data):
        """Handle messages from Frida scripts"""
        if message['type'] == 'send':
            payload = message['payload']
            print(f"[Script] {payload}")
            
            # Categorize and store data
            self.categorize_data(payload)
        
        elif message['type'] == 'error':
            print(f"[Error] {message['stack']}")
    
    def categorize_data(self, payload):
        """Categorize collected data"""
        payload_str = str(payload).lower()
        
        if 'http' in payload_str or 'url' in payload_str:
            self.data_collected['network_requests'].append({
                'timestamp': time.time(),
                'data': payload
            })
        elif 'file' in payload_str or 'read' in payload_str or 'write' in payload_str:
            self.data_collected['file_operations'].append({
                'timestamp': time.time(),
                'data': payload
            })
        elif 'crypto' in payload_str or 'encrypt' in payload_str or 'decrypt' in payload_str:
            self.data_collected['crypto_operations'].append({
                'timestamp': time.time(),
                'data': payload
            })
        else:
            self.data_collected['api_calls'].append({
                'timestamp': time.time(),
                'data': payload
            })
    
    def start_monitoring(self):
        """Start monitoring the target application"""
        try:
            # Try to attach to running process first
            try:
                pid = self.device.get_process(self.package_name).pid
                self.session = self.device.attach(pid)
                print(f"[+] Attached to running process: {self.package_name} (PID: {pid})")
            except:
                # Spawn the application
                pid = self.device.spawn([self.package_name])
                self.session = self.device.attach(pid)
                print(f"[+] Spawned application: {self.package_name} (PID: {pid})")
                self.device.resume(pid)
            
            # Load default scripts
            self.load_default_scripts()
            
            print("[+] Monitoring started. Press Ctrl+C to stop.")
            
            # Keep the script running
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n[+] Stopping monitoring...")
                self.generate_report()
                
        except Exception as e:
            print(f"[-] Error starting monitoring: {e}")
    
    def load_default_scripts(self):
        """Load commonly used scripts"""
        default_scripts = [
            ('frida_scripts/ssl_bypass/universal_ssl_bypass.js', 'SSL Bypass'),
            ('frida_scripts/anti_debug/root_bypass.js', 'Root Bypass'),
            ('frida_scripts/general/network_tracer.js', 'Network Tracer'),
            ('frida_scripts/general/file_monitor.js', 'File Monitor'),
            ('frida_scripts/general/crypto_logger.js', 'Crypto Logger')
        ]
        
        for script_path, script_name in default_scripts:
            self.load_script(script_path, script_name)
    
    def generate_report(self):
        """Generate analysis report"""
        report = {
            'package_name': self.package_name,
            'analysis_duration': time.time(),
            'data_collected': self.data_collected,
            'summary': {
                'total_network_requests': len(self.data_collected['network_requests']),
                'total_file_operations': len(self.data_collected['file_operations']),
                'total_crypto_operations': len(self.data_collected['crypto_operations']),
                'total_api_calls': len(self.data_collected['api_calls'])
            }
        }
        
        report_file = f"output/dynamic_analysis/{self.package_name}_report.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"[+] Report generated: {report_file}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python frida_automation.py <package_name>")
        sys.exit(1)
    
    package_name = sys.argv[1]
    automation = FridaAutomation(package_name)
    automation.start_monitoring()
```

## 🔧 Phase 6: Advanced Techniques

### 6.1 Memory Dumping and Analysis

#### Memory Scanner
```javascript
// frida_scripts/advanced/memory_scanner.js
Java.perform(() => {
    console.log("[+] Memory scanner loaded");
    
    function scanMemoryForPatterns() {
        const patterns = [
            'password',
            'token',
            'api_key',
            'secret',
            'bearer',
            'authorization'
        ];
        
        Process.enumerateRanges('r--').forEach(range => {
            try {
                const memory = Memory.readByteArray(range.base, Math.min(range.size, 1024 * 1024)); // 1MB max
                const content = uint8ArrayToString(new Uint8Array(memory));
                
                patterns.forEach(pattern => {
                    const regex = new RegExp(pattern + '[\\s\\S]{0,50}', 'gi');
                    const matches = content.match(regex);
                    if (matches) {
                        console.log(`[+] Pattern '${pattern}' found in memory:`);
                        matches.forEach(match => {
                            console.log(`    ${match.substring(0, 100)}...`);
                        });
                    }
                });
            } catch (err) {
                // Skip inaccessible memory regions
            }
        });
    }
    
    function uint8ArrayToString(uint8Array) {
        let result = '';
        for (let i = 0; i < uint8Array.length; i++) {
            const char = uint8Array[i];
            if (char >= 32 && char <= 126) { // Printable ASCII
                result += String.fromCharCode(char);
            } else {
                result += '.';
            }
        }
        return result;
    }
    
    // Scan memory every 30 seconds
    setInterval(scanMemoryForPatterns, 30000);
    
    // Initial scan
    scanMemoryForPatterns();
});
```

### 6.2 Class and Method Discovery

#### Runtime Class Explorer
```javascript
// frida_scripts/advanced/class_explorer.js
Java.perform(() => {
    console.log("[+] Runtime class explorer loaded");
    
    function exploreLoadedClasses() {
        console.log("[+] Enumerating loaded classes...");
        
        Java.enumerateLoadedClasses({
            onMatch: function(className) {
                if (className.includes("com.target.app")) {
                    console.log("[+] Found target class: " + className);
                    exploreClass(className);
                }
            },
            onComplete: function() {
                console.log("[+] Class enumeration complete");
            }
        });
    }
    
    function exploreClass(className) {
        try {
            const targetClass = Java.use(className);
            const methods = targetClass.class.getDeclaredMethods();
            
            console.log(`[+] Class: ${className}`);
            console.log(`    Methods (${methods.length}):`);
            
            methods.forEach(method => {
                console.log(`      ${method.getName()}(${method.getParameterTypes()})`);
            });
            
            const fields = targetClass.class.getDeclaredFields();
            console.log(`    Fields (${fields.length}):`);
            
            fields.forEach(field => {
                console.log(`      ${field.getName()}: ${field.getType()}`);
            });
            
        } catch (err) {
            console.log(`[-] Error exploring class ${className}: ${err}`);
        }
    }
    
    // Start exploration
    exploreLoadedClasses();
});
```

## 📊 Reporting and Analysis

### Generate Comprehensive Dynamic Analysis Report
```python
# scripts/dynamic_analysis/report_generator.py
import json
import datetime
from jinja2 import Template

class DynamicAnalysisReporter:
    def __init__(self, data_file):
        with open(data_file, 'r') as f:
            self.data = json.load(f)
    
    def generate_html_report(self, output_file):
        """Generate HTML report from collected data"""
        
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Dynamic Analysis Report - {{ package_name }}</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; }
                .finding { margin: 10px 0; padding: 10px; background: #f5f5f5; }
                .critical { border-left: 4px solid #d32f2f; }
                .high { border-left: 4px solid #f57c00; }
                .medium { border-left: 4px solid #1976d2; }
                .low { border-left: 4px solid #388e3c; }
                pre { background: #f0f0f0; padding: 10px; overflow-x: auto; }
                table { width: 100%; border-collapse: collapse; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
            </style>
        </head>
        <body>
            <h1>Dynamic Analysis Report</h1>
            <h2>Package: {{ package_name }}</h2>
            <p>Generated: {{ timestamp }}</p>
            
            <div class="section">
                <h3>Executive Summary</h3>
                <table>
                    <tr><th>Metric</th><th>Count</th></tr>
                    <tr><td>Network Requests</td><td>{{ summary.total_network_requests }}</td></tr>
                    <tr><td>File Operations</td><td>{{ summary.total_file_operations }}</td></tr>
                    <tr><td>Crypto Operations</td><td>{{ summary.total_crypto_operations }}</td></tr>
                    <tr><td>API Calls</td><td>{{ summary.total_api_calls }}</td></tr>
                </table>
            </div>
            
            <div class="section">
                <h3>Network Activity</h3>
                {% for request in data_collected.network_requests[:10] %}
                <div class="finding medium">
                    <strong>{{ request.timestamp }}</strong><br>
                    <pre>{{ request.data }}</pre>
                </div>
                {% endfor %}
            </div>
            
            <div class="section">
                <h3>File System Activity</h3>
                {% for operation in data_collected.file_operations[:10] %}
                <div class="finding low">
                    <strong>{{ operation.timestamp }}</strong><br>
                    <pre>{{ operation.data }}</pre>
                </div>
                {% endfor %}
            </div>
            
            <div class="section">
                <h3>Cryptographic Operations</h3>
                {% for crypto in data_collected.crypto_operations %}
                <div class="finding high">
                    <strong>{{ crypto.timestamp }}</strong><br>
                    <pre>{{ crypto.data }}</pre>
                </div>
                {% endfor %}
            </div>
            
        </body>
        </html>
        """
        
        template = Template(html_template)
        
        report_html = template.render(
            package_name=self.data['package_name'],
            timestamp=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            summary=self.data['summary'],
            data_collected=self.data['data_collected']
        )
        
        with open(output_file, 'w') as f:
            f.write(report_html)
        
        print(f"[+] HTML report generated: {output_file}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python report_generator.py <data_file.json>")
        sys.exit(1)
    
    reporter = DynamicAnalysisReporter(sys.argv[1])
    reporter.generate_html_report("dynamic_analysis_report.html")
```

## 🎯 Best Practices

### 1. Systematic Approach
- Start with basic hooking before advanced techniques
- Use multiple bypass scripts for comprehensive coverage
- Document all findings with timestamps and context

### 2. Tool Combination
- **Frida** for runtime manipulation
- **Objection** for quick exploration
- **Burp Suite** for traffic analysis
- **Wireshark** for low-level network analysis

### 3. Stealth Techniques
- Rename frida-server to avoid detection
- Use spawning mode for better hook timing
- Implement anti-detection bypasses

### 4. Data Collection
- Log all security-relevant operations
- Capture network traffic for offline analysis
- Monitor file system and database changes

## 🚀 Next Steps

1. ✅ Dynamic Analysis Complete
2. 🔐 Continue to [Authentication Analysis](04-authentication-analysis.md)
3. 🛡️ Study [Anti-Debugging Bypass](05-anti-debugging-bypass.md)

## 📚 References

- [Frida Documentation](https://frida.re/docs/)
- [Objection Guide](https://github.com/sensepost/objection)
- [Burp Suite Mobile Testing](https://portswigger.net/burp/documentation/desktop/mobile)
- [Android Hooking and Dynamic Analysis](https://github.com/OWASP/owasp-mstg)
- [Drozer User Guide](https://labs.withsecure.com/tools/drozer/)
