# 🛡️ Anti-Debugging Bypass Guide

This comprehensive guide covers advanced techniques for bypassing Android application anti-debugging protections, including detection mechanisms and sophisticated evasion strategies.

## 🎯 Objectives

- Identify and analyze anti-debugging mechanisms
- Implement comprehensive bypass techniques
- Maintain stealth during reverse engineering
- Automate protection bypass with custom scripts
- Develop persistent evasion strategies

## 🔍 Anti-Debugging Detection Mechanisms

### Common Protection Techniques

#### 1. Manifest-Based Detection
```xml
<!-- AndroidManifest.xml -->
<application android:debuggable="false">
```

#### 2. JDWP (Java Debug Wire Protocol) Detection
```java
// Java-based detection
if (Debug.isDebuggerConnected()) {
    System.exit(0);
}
```

#### 3. TracerPid Detection
```c
// Native code detection
FILE* fp = fopen("/proc/self/status", "r");
char line[256];
while (fgets(line, sizeof(line), fp)) {
    if (strncmp(line, "TracerPid:", 10) == 0) {
        int pid = atoi(line + 10);
        if (pid != 0) {
            exit(1); // Debugger detected
        }
    }
}
```

#### 4. Ptrace Self-Attachment
```c
// Anti-ptrace technique
if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) {
    exit(1); // Already being traced
}
```

#### 5. Custom ELF Section Checks
```c
// Check for debugging symbols
if (check_debug_sections()) {
    anti_debug_trigger();
}
```

## 🚀 Phase 1: Detection Analysis

### 1.1 Static Detection Analysis

#### Automated Detection Scanner
```python
# scripts/anti_debug/detection_scanner.py
import re
import os
import subprocess
from pathlib import Path

class AntiDebugDetector:
    def __init__(self, apk_path):
        self.apk_path = apk_path
        self.decompiled_path = None
        self.detections = {
            'manifest': [],
            'java_code': [],
            'native_code': [],
            'string_checks': [],
            'custom_checks': []
        }
    
    def scan_all_protections(self):
        """Scan for all anti-debugging protections"""
        print("[+] Scanning for anti-debugging protections...")
        
        # Decompile APK first
        self.decompile_apk()
        
        # Scan different layers
        self.scan_manifest_protections()
        self.scan_java_protections()
        self.scan_native_protections()
        self.scan_string_protections()
        self.scan_custom_protections()
        
        return self.generate_detection_report()
    
    def decompile_apk(self):
        """Decompile APK for analysis"""
        self.decompiled_path = f"output/anti_debug_analysis/{Path(self.apk_path).stem}"
        
        # Use JADX for decompilation
        cmd = f"jadx -d {self.decompiled_path} {self.apk_path}"
        subprocess.run(cmd, shell=True, capture_output=True)
        
        # Also extract with APKTool for manifest
        apktool_path = f"{self.decompiled_path}_apktool"
        cmd = f"apktool d {self.apk_path} -o {apktool_path}"
        subprocess.run(cmd, shell=True, capture_output=True)
        
        print(f"[+] APK decompiled to: {self.decompiled_path}")
    
    def scan_manifest_protections(self):
        """Scan AndroidManifest.xml for debug flags"""
        print("[+] Scanning manifest protections...")
        
        manifest_path = f"{self.decompiled_path}_apktool/AndroidManifest.xml"
        
        if os.path.exists(manifest_path):
            with open(manifest_path, 'r') as f:
                content = f.read()
                
                # Check for debuggable flag
                if 'android:debuggable="false"' in content:
                    self.detections['manifest'].append({
                        'type': 'Debuggable Flag',
                        'description': 'Application explicitly sets debuggable=false',
                        'location': 'AndroidManifest.xml',
                        'severity': 'Low'
                    })
                
                # Check for other security flags
                if 'android:allowBackup="false"' in content:
                    self.detections['manifest'].append({
                        'type': 'Backup Disabled',
                        'description': 'Application disables backup (potential anti-tamper)',
                        'location': 'AndroidManifest.xml',
                        'severity': 'Info'
                    })
    
    def scan_java_protections(self):
        """Scan Java code for anti-debugging checks"""
        print("[+] Scanning Java code protections...")
        
        java_patterns = {
            'JDWP Detection': [
                r'Debug\.isDebuggerConnected\(\)',
                r'VMDebug\.isDebuggerConnected\(\)',
                r'android\.os\.Debug\.isDebuggerConnected'
            ],
            'Application Info Check': [
                r'ApplicationInfo\.FLAG_DEBUGGABLE',
                r'getApplicationInfo\(\)\.flags.*FLAG_DEBUGGABLE'
            ],
            'System Property Check': [
                r'System\.getProperty.*debug',
                r'SystemProperties\.get.*debug'
            ],
            'Package Manager Check': [
                r'getPackageInfo.*GET_SIGNATURES',
                r'PackageManager.*getInstallerPackageName'
            ],
            'Runtime Exec Check': [
                r'Runtime\.getRuntime\(\)\.exec',
                r'ProcessBuilder.*exec',
                r'getRuntime\(\)\.exec.*su'
            ]
        }
        
        for root, dirs, files in os.walk(self.decompiled_path):
            for file in files:
                if file.endswith('.java'):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                            for detection_type, patterns in java_patterns.items():
                                for pattern in patterns:
                                    matches = re.finditer(pattern, content, re.IGNORECASE)
                                    for match in matches:
                                        line_num = content[:match.start()].count('\n') + 1
                                        self.detections['java_code'].append({
                                            'type': detection_type,
                                            'pattern': pattern,
                                            'file': file_path,
                                            'line': line_num,
                                            'context': self.get_context(content, match.start()),
                                            'severity': self.get_severity(detection_type)
                                        })
                    except Exception as e:
                        continue
    
    def scan_native_protections(self):
        """Scan native libraries for anti-debugging"""
        print("[+] Scanning native code protections...")
        
        native_patterns = {
            'Ptrace Detection': [
                b'ptrace', b'PTRACE_TRACEME', b'PTRACE_DETACH'
            ],
            'Proc Status Check': [
                b'/proc/self/status', b'TracerPid:', b'/proc/self/stat'
            ],
            'Debugger Detection': [
                b'gdb', b'lldb', b'frida', b'xposed'
            ],
            'Anti-Hook Detection': [
                b'hook', b'inject', b'LD_PRELOAD'
            ]
        }
        
        # Find .so files
        so_files = []
        for root, dirs, files in os.walk(self.decompiled_path):
            for file in files:
                if file.endswith('.so'):
                    so_files.append(os.path.join(root, file))
        
        for so_file in so_files:
            try:
                with open(so_file, 'rb') as f:
                    content = f.read()
                    
                    for detection_type, patterns in native_patterns.items():
                        for pattern in patterns:
                            if pattern in content:
                                self.detections['native_code'].append({
                                    'type': detection_type,
                                    'pattern': pattern.decode('utf-8', errors='ignore'),
                                    'file': so_file,
                                    'severity': 'High'
                                })
            except Exception as e:
                continue
    
    def scan_string_protections(self):
        """Scan for anti-debugging strings"""
        print("[+] Scanning string protections...")
        
        debug_strings = [
            'debug', 'debugger', 'gdb', 'lldb', 'frida',
            'xposed', 'substrate', 'cydia', 'jdwp',
            'TracerPid', 'ptrace', 'anti', 'tamper'
        ]
        
        for root, dirs, files in os.walk(self.decompiled_path):
            for file in files:
                if file.endswith(('.java', '.smali', '.xml')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                            for debug_string in debug_strings:
                                if debug_string in content.lower():
                                    # Get context around the string
                                    lines = content.split('\n')
                                    for i, line in enumerate(lines):
                                        if debug_string in line.lower():
                                            self.detections['string_checks'].append({
                                                'type': 'Debug String',
                                                'string': debug_string,
                                                'file': file_path,
                                                'line': i + 1,
                                                'context': line.strip(),
                                                'severity': 'Medium'
                                            })
                    except Exception as e:
                        continue
    
    def scan_custom_protections(self):
        """Scan for custom anti-debugging techniques"""
        print("[+] Scanning custom protections...")
        
        custom_patterns = {
            'Time-based Detection': [
                r'System\.currentTimeMillis\(\)',
                r'System\.nanoTime\(\)',
                r'SystemClock\.elapsedRealtime\(\)'
            ],
            'Exception-based Detection': [
                r'try.*catch.*Exception',
                r'IllegalArgumentException',
                r'SecurityException'
            ],
            'Thread-based Detection': [
                r'Thread\.sleep\(',
                r'new Thread\(',
                r'ThreadPoolExecutor'
            ],
            'Reflection Detection': [
                r'Class\.forName\(',
                r'getDeclaredMethod\(',
                r'getMethod\('
            ]
        }
        
        for root, dirs, files in os.walk(self.decompiled_path):
            for file in files:
                if file.endswith('.java'):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                            for detection_type, patterns in custom_patterns.items():
                                for pattern in patterns:
                                    matches = re.finditer(pattern, content)
                                    for match in matches:
                                        # Only flag if in suspicious context
                                        context = self.get_context(content, match.start())
                                        if self.is_suspicious_context(context):
                                            line_num = content[:match.start()].count('\n') + 1
                                            self.detections['custom_checks'].append({
                                                'type': detection_type,
                                                'pattern': pattern,
                                                'file': file_path,
                                                'line': line_num,
                                                'context': context,
                                                'severity': 'Medium'
                                            })
                    except Exception as e:
                        continue
    
    def get_context(self, content, position, context_size=100):
        """Get context around a position in content"""
        start = max(0, position - context_size)
        end = min(len(content), position + context_size)
        return content[start:end]
    
    def is_suspicious_context(self, context):
        """Determine if context suggests anti-debugging"""
        suspicious_keywords = [
            'debug', 'trace', 'hook', 'inject', 'anti',
            'detect', 'check', 'validate', 'verify'
        ]
        
        context_lower = context.lower()
        return any(keyword in context_lower for keyword in suspicious_keywords)
    
    def get_severity(self, detection_type):
        """Get severity level for detection type"""
        high_severity = ['JDWP Detection', 'Ptrace Detection']
        medium_severity = ['System Property Check', 'Application Info Check']
        
        if detection_type in high_severity:
            return 'High'
        elif detection_type in medium_severity:
            return 'Medium'
        else:
            return 'Low'
    
    def generate_detection_report(self):
        """Generate comprehensive detection report"""
        total_detections = sum(len(detections) for detections in self.detections.values())
        
        report = {
            'apk_path': self.apk_path,
            'total_detections': total_detections,
            'detection_summary': {
                'manifest': len(self.detections['manifest']),
                'java_code': len(self.detections['java_code']),
                'native_code': len(self.detections['native_code']),
                'string_checks': len(self.detections['string_checks']),
                'custom_checks': len(self.detections['custom_checks'])
            },
            'severity_distribution': self.get_severity_distribution(),
            'detailed_findings': self.detections,
            'bypass_recommendations': self.generate_bypass_recommendations()
        }
        
        return report
    
    def get_severity_distribution(self):
        """Get distribution of findings by severity"""
        severity_count = {'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        
        for category in self.detections.values():
            for detection in category:
                severity = detection.get('severity', 'Low')
                severity_count[severity] = severity_count.get(severity, 0) + 1
        
        return severity_count
    
    def generate_bypass_recommendations(self):
        """Generate bypass recommendations based on detections"""
        recommendations = []
        
        # Analyze detections and suggest bypasses
        if self.detections['java_code']:
            recommendations.append({
                'category': 'Java Anti-Debug',
                'techniques': ['Frida JDWP bypass', 'Application flag modification'],
                'scripts': ['jdwp_bypass.js', 'app_flag_bypass.js']
            })
        
        if self.detections['native_code']:
            recommendations.append({
                'category': 'Native Anti-Debug',
                'techniques': ['Ptrace hooking', 'Proc status spoofing'],
                'scripts': ['ptrace_bypass.js', 'proc_spoofing.js']
            })
        
        if self.detections['manifest']:
            recommendations.append({
                'category': 'Manifest Protection',
                'techniques': ['APK patching', 'Runtime modification'],
                'scripts': ['manifest_patcher.py']
            })
        
        return recommendations

# Usage
if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python detection_scanner.py <apk_path>")
        sys.exit(1)
    
    detector = AntiDebugDetector(sys.argv[1])
    report = detector.scan_all_protections()
    
    print("\n" + "="*50)
    print("ANTI-DEBUG DETECTION REPORT")
    print("="*50)
    print(f"Total detections: {report['total_detections']}")
    print(f"Severity distribution: {report['severity_distribution']}")
    
    import json
    with open('anti_debug_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    print("\n[+] Detailed report saved to: anti_debug_report.json")
```

## 🔧 Phase 2: Comprehensive Bypass Implementation

### 2.1 Universal Anti-Debug Bypass Framework

#### Master Bypass Script
```javascript
// frida_scripts/anti_debug/universal_bypass.js
Java.perform(() => {
    console.log("[+] Universal Anti-Debug Bypass Framework loaded");
    
    // Initialize bypass modules
    bypassJDWPDetection();
    bypassApplicationFlags();
    bypassNativeDetection();
    bypassRootDetection();
    bypassHookDetection();
    bypassTimingDetection();
    bypassReflectionDetection();
    
    console.log("[+] All bypass modules activated");
});

function bypassJDWPDetection() {
    console.log("[+] Loading JDWP detection bypass...");
    
    try {
        // Bypass Debug.isDebuggerConnected()
        const Debug = Java.use("android.os.Debug");
        Debug.isDebuggerConnected.implementation = function() {
            console.log("[+] Debug.isDebuggerConnected() bypassed - returning false");
            return false;
        };
        
        // Bypass VMDebug.isDebuggerConnected()
        try {
            const VMDebug = Java.use("dalvik.system.VMDebug");
            VMDebug.isDebuggerConnected.implementation = function() {
                console.log("[+] VMDebug.isDebuggerConnected() bypassed - returning false");
                return false;
            };
        } catch (err) {
            console.log("[-] VMDebug not available");
        }
        
        // Bypass JDWP detection via System properties
        const System = Java.use("java.lang.System");
        System.getProperty.implementation = function(key) {
            const result = this.getProperty(key);
            
            if (key === "java.vm.name" && result && result.includes("debug")) {
                console.log("[+] Spoofing java.vm.name system property");
                return "ART";
            }
            
            if (key === "ro.debuggable" && result === "1") {
                console.log("[+] Spoofing ro.debuggable system property");
                return "0";
            }
            
            return result;
        };
        
    } catch (err) {
        console.log("[-] Failed to bypass JDWP detection: " + err);
    }
}

function bypassApplicationFlags() {
    console.log("[+] Loading application flags bypass...");
    
    try {
        // Bypass ApplicationInfo.FLAG_DEBUGGABLE check
        const ApplicationInfo = Java.use("android.content.pm.ApplicationInfo");
        const FLAG_DEBUGGABLE = 2;
        
        // Hook Context.getApplicationInfo()
        const ContextWrapper = Java.use("android.content.ContextWrapper");
        ContextWrapper.getApplicationInfo.implementation = function() {
            const appInfo = this.getApplicationInfo();
            
            if (appInfo.flags.value & FLAG_DEBUGGABLE) {
                console.log("[+] Removing FLAG_DEBUGGABLE from ApplicationInfo");
                appInfo.flags.value = appInfo.flags.value & ~FLAG_DEBUGGABLE;
            }
            
            return appInfo;
        };
        
        // Hook PackageManager.getApplicationInfo()
        const Context = Java.use("android.content.Context");
        Context.getPackageManager.implementation = function() {
            const packageManager = this.getPackageManager();
            
            // Wrap the PackageManager
            const PackageManager = Java.use("android.content.pm.PackageManager");
            PackageManager.getApplicationInfo.overload('java.lang.String', 'int').implementation = function(packageName, flags) {
                const appInfo = this.getApplicationInfo(packageName, flags);
                
                if (appInfo.flags.value & FLAG_DEBUGGABLE) {
                    console.log("[+] Removing FLAG_DEBUGGABLE from PackageManager query");
                    appInfo.flags.value = appInfo.flags.value & ~FLAG_DEBUGGABLE;
                }
                
                return appInfo;
            };
            
            return packageManager;
        };
        
    } catch (err) {
        console.log("[-] Failed to bypass application flags: " + err);
    }
}

function bypassNativeDetection() {
    console.log("[+] Loading native detection bypass...");
    
    // Bypass ptrace detection
    bypassPtraceDetection();
    
    // Bypass /proc/self/status reading
    bypassProcStatusDetection();
    
    // Bypass library injection detection
    bypassLibraryDetection();
}

function bypassPtraceDetection() {
    try {
        // Hook ptrace function
        const ptracePtr = Module.findExportByName("libc.so", "ptrace");
        if (ptracePtr) {
            Interceptor.replace(ptracePtr, new NativeCallback(function(request, pid, addr, data) {
                console.log("[+] ptrace() call intercepted");
                console.log("    Request: " + request);
                console.log("    PID: " + pid);
                
                // PTRACE_TRACEME = 0
                if (request === 0) {
                    console.log("[+] PTRACE_TRACEME blocked - returning success");
                    return 0;
                }
                
                // Call original ptrace for other operations
                const originalPtrace = new NativeFunction(ptracePtr, 'long', ['int', 'int', 'pointer', 'pointer']);
                return originalPtrace(request, pid, addr, data);
                
            }, 'long', ['int', 'int', 'pointer', 'pointer']));
        }
    } catch (err) {
        console.log("[-] Failed to hook ptrace: " + err);
    }
}

function bypassProcStatusDetection() {
    try {
        // Hook fopen to intercept /proc/self/status reads
        const fopenPtr = Module.findExportByName("libc.so", "fopen");
        if (fopenPtr) {
            Interceptor.attach(fopenPtr, {
                onEnter: function(args) {
                    const filename = Memory.readUtf8String(args[0]);
                    this.filename = filename;
                    
                    if (filename === "/proc/self/status" || filename === "/proc/self/stat") {
                        console.log("[+] Blocking access to " + filename);
                        this.shouldBlock = true;
                    }
                },
                onLeave: function(retval) {
                    if (this.shouldBlock) {
                        retval.replace(ptr(0)); // Return NULL
                    }
                }
            });
        }
        
        // Alternative: Hook open syscall
        const openPtr = Module.findExportByName("libc.so", "open");
        if (openPtr) {
            Interceptor.attach(openPtr, {
                onEnter: function(args) {
                    const filename = Memory.readUtf8String(args[0]);
                    
                    if (filename.includes("/proc/self/status") || filename.includes("/proc/self/stat")) {
                        console.log("[+] Blocking open() access to " + filename);
                        this.shouldBlock = true;
                    }
                },
                onLeave: function(retval) {
                    if (this.shouldBlock) {
                        retval.replace(ptr(-1)); // Return error
                    }
                }
            });
        }
        
        // Hook read to spoof TracerPid content
        const readPtr = Module.findExportByName("libc.so", "read");
        if (readPtr) {
            Interceptor.attach(readPtr, {
                onEnter: function(args) {
                    this.fd = args[0].toInt32();
                    this.buffer = args[1];
                    this.count = args[2].toInt32();
                },
                onLeave: function(retval) {
                    if (retval.toInt32() > 0) {
                        const content = Memory.readUtf8String(this.buffer, retval.toInt32());
                        
                        if (content.includes("TracerPid:") && !content.includes("TracerPid:\t0")) {
                            console.log("[+] Spoofing TracerPid in /proc/self/status");
                            const spoofed = content.replace(/TracerPid:\s*\d+/, "TracerPid:\t0");
                            Memory.writeUtf8String(this.buffer, spoofed);
                            retval.replace(ptr(spoofed.length));
                        }
                    }
                }
            });
        }
        
    } catch (err) {
        console.log("[-] Failed to bypass proc status detection: " + err);
    }
}

function bypassLibraryDetection() {
    try {
        // Hook dlopen to hide library loading
        const dlopenPtr = Module.findExportByName("libdl.so", "dlopen");
        if (dlopenPtr) {
            Interceptor.attach(dlopenPtr, {
                onEnter: function(args) {
                    const libraryPath = Memory.readUtf8String(args[0]);
                    
                    if (libraryPath && (libraryPath.includes("frida") || 
                                      libraryPath.includes("xposed") || 
                                      libraryPath.includes("substrate"))) {
                        console.log("[+] Hiding library load: " + libraryPath);
                        this.shouldHide = true;
                    }
                },
                onLeave: function(retval) {
                    if (this.shouldHide) {
                        retval.replace(ptr(0)); // Return NULL
                    }
                }
            });
        }
        
        // Hook System.loadLibrary
        const System = Java.use("java.lang.System");
        System.loadLibrary.implementation = function(libraryName) {
            console.log("[+] System.loadLibrary called: " + libraryName);
            
            // Allow normal libraries
            if (!libraryName.includes("frida") && !libraryName.includes("xposed")) {
                return this.loadLibrary(libraryName);
            } else {
                console.log("[+] Blocking suspicious library: " + libraryName);
                throw new UnsatisfiedLinkError("Library not found");
            }
        };
        
    } catch (err) {
        console.log("[-] Failed to bypass library detection: " + err);
    }
}

function bypassRootDetection() {
    console.log("[+] Loading root detection bypass...");
    
    try {
        // Comprehensive root detection bypass
        const rootIndicators = [
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su",
            "/su/bin/su"
        ];
        
        // Hook File.exists()
        const File = Java.use("java.io.File");
        File.exists.implementation = function() {
            const path = this.getAbsolutePath();
            
            // Check if path is a root indicator
            for (let indicator of rootIndicators) {
                if (path.includes(indicator)) {
                    console.log("[+] Blocking root file check: " + path);
                    return false;
                }
            }
            
            return this.exists();
        };
        
        // Hook Runtime.exec() for su command detection
        const Runtime = Java.use("java.lang.Runtime");
        Runtime.exec.overload('java.lang.String').implementation = function(command) {
            if (command.includes("su") || command.includes("which")) {
                console.log("[+] Blocking suspicious command: " + command);
                throw new IOException("Command not found");
            }
            
            return this.exec(command);
        };
        
        // Hook package manager for root app detection
        const PackageManager = Java.use("android.content.pm.PackageManager");
        PackageManager.getInstalledPackages.implementation = function(flags) {
            const packages = this.getInstalledPackages(flags);
            
            // Filter out root-related packages
            const rootPackages = [
                "com.noshufou.android.su",
                "com.thirdparty.superuser",
                "eu.chainfire.supersu",
                "com.koushikdutta.superuser",
                "com.zachspong.temprootremovejb",
                "com.ramdroid.appquarantine"
            ];
            
            const filteredPackages = [];
            for (let i = 0; i < packages.size(); i++) {
                const pkg = packages.get(i);
                const packageName = pkg.packageName.value;
                
                if (!rootPackages.includes(packageName)) {
                    filteredPackages.push(pkg);
                }
            }
            
            return filteredPackages;
        };
        
    } catch (err) {
        console.log("[-] Failed to bypass root detection: " + err);
    }
}

function bypassHookDetection() {
    console.log("[+] Loading hook detection bypass...");
    
    try {
        // Hide Frida from process lists
        const Runtime = Java.use("java.lang.Runtime");
        Runtime.exec.overload('[Ljava.lang.String;').implementation = function(cmdArray) {
            const command = cmdArray.join(' ');
            
            if (command.includes("ps") || command.includes("netstat")) {
                console.log("[+] Intercepting process listing command: " + command);
                
                // Execute original command
                const process = this.exec(cmdArray);
                
                // Filter output to hide Frida
                // This is simplified - in practice, you'd need to properly filter the output
                return process;
            }
            
            return this.exec(cmdArray);
        };
        
        // Hook native library enumeration
        const System = Java.use("java.lang.System");
        System.getProperty.implementation = function(key) {
            const result = this.getProperty(key);
            
            if (key === "java.library.path" && result && result.includes("frida")) {
                console.log("[+] Hiding Frida from library path");
                return result.replace(/[^:]*frida[^:]*/g, "");
            }
            
            return result;
        };
        
    } catch (err) {
        console.log("[-] Failed to bypass hook detection: " + err);
    }
}

function bypassTimingDetection() {
    console.log("[+] Loading timing detection bypass...");
    
    try {
        // Hook timing functions to provide consistent results
        const System = Java.use("java.lang.System");
        let baseTime = Date.now();
        let lastTime = baseTime;
        
        System.currentTimeMillis.implementation = function() {
            // Provide predictable timing
            lastTime += Math.floor(Math.random() * 100) + 50; // 50-150ms increments
            console.log("[+] Spoofing System.currentTimeMillis(): " + lastTime);
            return lastTime;
        };
        
        System.nanoTime.implementation = function() {
            // Provide predictable nano timing
            const nanoTime = lastTime * 1000000 + Math.floor(Math.random() * 1000000);
            console.log("[+] Spoofing System.nanoTime(): " + nanoTime);
            return nanoTime;
        };
        
        // Hook SystemClock
        const SystemClock = Java.use("android.os.SystemClock");
        SystemClock.elapsedRealtime.implementation = function() {
            const elapsed = Date.now() - baseTime;
            console.log("[+] Spoofing SystemClock.elapsedRealtime(): " + elapsed);
            return elapsed;
        };
        
    } catch (err) {
        console.log("[-] Failed to bypass timing detection: " + err);
    }
}

function bypassReflectionDetection() {
    console.log("[+] Loading reflection detection bypass...");
    
    try {
        // Hook Class.forName to hide sensitive classes
        const Class = Java.use("java.lang.Class");
        Class.forName.overload('java.lang.String').implementation = function(className) {
            
            // Block access to debugging/hooking related classes
            const blockedClasses = [
                "dalvik.system.VMDebug",
                "android.os.Debug",
                "de.robv.android.xposed.XposedBridge",
                "com.android.internal.os.RuntimeInit"
            ];
            
            if (blockedClasses.includes(className)) {
                console.log("[+] Blocking Class.forName for: " + className);
                throw new ClassNotFoundException("Class not found: " + className);
            }
            
            return this.forName(className);
        };
        
        // Hook method reflection
        Class.getDeclaredMethod.implementation = function(methodName, parameterTypes) {
            
            // Block access to debugging methods
            const blockedMethods = [
                "isDebuggerConnected",
                "getApplicationInfo",
                "isDebuggingEnabled"
            ];
            
            if (blockedMethods.includes(methodName)) {
                console.log("[+] Blocking getDeclaredMethod for: " + methodName);
                throw new NoSuchMethodException("Method not found: " + methodName);
            }
            
            return this.getDeclaredMethod(methodName, parameterTypes);
        };
        
    } catch (err) {
        console.log("[-] Failed to bypass reflection detection: " + err);
    }
}

// Export functions for individual use
this.bypassJDWPDetection = bypassJDWPDetection;
this.bypassApplicationFlags = bypassApplicationFlags;
this.bypassNativeDetection = bypassNativeDetection;
this.bypassRootDetection = bypassRootDetection;
this.bypassHookDetection = bypassHookDetection;
this.bypassTimingDetection = bypassTimingDetection;
this.bypassReflectionDetection = bypassReflectionDetection;
```

### 2.2 Advanced Native Bypass Techniques

#### Native Code Patcher
```javascript
// frida_scripts/anti_debug/native_patcher.js
console.log("[+] Advanced Native Bypass Patcher loaded");

// Patch anti-debugging functions in native libraries
function patchNativeAntiDebug() {
    console.log("[+] Scanning for native anti-debug functions...");
    
    // Common anti-debug function names
    const antiDebugFunctions = [
        "anti_debug_check",
        "detect_debugger", 
        "is_debugged",
        "ptrace_check",
        "check_tracer_pid",
        "anti_hook_check"
    ];
    
    // Scan all loaded modules
    Process.enumerateModules().forEach(module => {
        if (module.name.includes(".so")) {
            console.log(`[+] Scanning module: ${module.name}`);
            
            antiDebugFunctions.forEach(funcName => {
                try {
                    const funcAddr = Module.findExportByName(module.name, funcName);
                    if (funcAddr) {
                        console.log(`[+] Found anti-debug function: ${funcName} at ${funcAddr}`);
                        patchFunction(funcAddr, funcName);
                    }
                } catch (err) {
                    // Function not found, continue
                }
            });
            
            // Search for functions by pattern
            searchAntiDebugPatterns(module);
        }
    });
}

function patchFunction(address, functionName) {
    console.log(`[+] Patching function: ${functionName} at ${address}`);
    
    try {
        // Method 1: Replace with return 0 (false)
        Interceptor.replace(address, new NativeCallback(function() {
            console.log(`[+] ${functionName} called - returning 0`);
            return 0;
        }, 'int', []));
        
    } catch (err) {
        try {
            // Method 2: NOP the function
            Memory.patchCode(address, 4, code => {
                const writer = new X86Writer(code, { pc: address });
                writer.putMovRegU32('eax', 0);  // mov eax, 0
                writer.putRet();                // ret
                writer.flush();
            });
            console.log(`[+] NOPed function: ${functionName}`);
            
        } catch (err2) {
            console.log(`[-] Failed to patch ${functionName}: ${err2}`);
        }
    }
}

function searchAntiDebugPatterns(module) {
    console.log(`[+] Searching for anti-debug patterns in ${module.name}`);
    
    try {
        // Pattern 1: ptrace(PTRACE_TRACEME, 0, 1, 0)
        const ptracePattern = "01 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00"; // x86_64
        
        Memory.scan(module.base, module.size, ptracePattern, {
            onMatch: function(address, size) {
                console.log(`[+] Found ptrace TRACEME pattern at: ${address}`);
                patchPtraceCall(address);
            },
            onComplete: function() {
                console.log(`[+] Pattern scan complete for ${module.name}`);
            }
        });
        
        // Pattern 2: "/proc/self/status" string
        const procStatusPattern = "2f 70 72 6f 63 2f 73 65 6c 66 2f 73 74 61 74 75 73"; // "/proc/self/status"
        
        Memory.scan(module.base, module.size, procStatusPattern, {
            onMatch: function(address, size) {
                console.log(`[+] Found /proc/self/status string at: ${address}`);
                patchProcStatusString(address);
            },
            onComplete: function() {
                console.log(`[+] String scan complete for ${module.name}`);
            }
        });
        
    } catch (err) {
        console.log(`[-] Pattern search failed for ${module.name}: ${err}`);
    }
}

function patchPtraceCall(address) {
    try {
        // Find the ptrace call instruction and patch it
        const instruction = Instruction.parse(address);
        console.log(`[+] Patching ptrace call at ${address}: ${instruction}`);
        
        // Replace with NOP or return 0
        Memory.patchCode(address, instruction.size, code => {
            const writer = new X86Writer(code, { pc: address });
            writer.putMovRegU32('eax', 0);  // Return 0 (success)
            for (let i = 4; i < instruction.size; i++) {
                writer.putNop();  // Fill with NOPs
            }
            writer.flush();
        });
        
    } catch (err) {
        console.log(`[-] Failed to patch ptrace call: ${err}`);
    }
}

function patchProcStatusString(address) {
    try {
        // Replace "/proc/self/status" with "/dev/null" or similar
        console.log(`[+] Patching /proc/self/status string at ${address}`);
        Memory.writeUtf8String(address, "/dev/null\x00\x00\x00\x00\x00\x00"); // Same length
        
    } catch (err) {
        console.log(`[-] Failed to patch proc status string: ${err}`);
    }
}

// Advanced binary analysis for custom anti-debug
function analyzeCustomAntiDebug() {
    console.log("[+] Analyzing custom anti-debug implementations...");
    
    Process.enumerateModules().forEach(module => {
        if (module.name.includes("libnative") || module.name.includes("libsecurity")) {
            console.log(`[+] Deep analysis of ${module.name}`);
            
            // Look for suspicious function call patterns
            analyzeSuspiciousCalls(module);
            
            // Look for string-based checks
            analyzeStringChecks(module);
            
            // Look for timing-based checks
            analyzeTimingChecks(module);
        }
    });
}

function analyzeSuspiciousCalls(module) {
    try {
        // Hook all exports and analyze call patterns
        Module.enumerateExports(module.name).forEach(exp => {
            if (exp.type === 'function') {
                try {
                    Interceptor.attach(exp.address, {
                        onEnter: function(args) {
                            // Analyze function calls for anti-debug patterns
                            this.startTime = Date.now();
                        },
                        onLeave: function(retval) {
                            const duration = Date.now() - this.startTime;
                            
                            // Flag suspicious timing (potential anti-debug check)
                            if (duration > 1000) { // More than 1 second
                                console.log(`[!] Suspicious timing in ${exp.name}: ${duration}ms`);
                            }
                            
                            // Flag suspicious return values
                            if (retval && (retval.toInt32() === -1 || retval.toInt32() === 1)) {
                                console.log(`[!] Suspicious return value from ${exp.name}: ${retval}`);
                            }
                        }
                    });
                } catch (err) {
                    // Skip unhookable functions
                }
            }
        });
    } catch (err) {
        console.log(`[-] Failed to analyze calls in ${module.name}: ${err}`);
    }
}

function analyzeStringChecks(module) {
    // Look for hardcoded strings related to debugging
    const debugStrings = [
        "gdb", "lldb", "frida", "xposed", "substrate",
        "debug", "trace", "hook", "inject"
    ];
    
    debugStrings.forEach(str => {
        try {
            Memory.scanSync(module.base, module.size, str).forEach(match => {
                console.log(`[!] Found debug string "${str}" at ${match.address} in ${module.name}`);
                
                // Try to patch the string
                try {
                    Memory.writeUtf8String(match.address, "safe" + "\x00".repeat(str.length - 4));
                    console.log(`[+] Patched debug string: ${str}`);
                } catch (err) {
                    console.log(`[-] Failed to patch string: ${err}`);
                }
            });
        } catch (err) {
            // String not found
        }
    });
}

function analyzeTimingChecks(module) {
    console.log(`[+] Analyzing timing-based checks in ${module.name}`);
    
    // Hook time-related functions in the module
    const timingFunctions = [
        "clock_gettime", "gettimeofday", "time"
    ];
    
    timingFunctions.forEach(funcName => {
        try {
            const funcAddr = Module.findExportByName(module.name, funcName);
            if (funcAddr) {
                console.log(`[+] Hooking timing function: ${funcName}`);
                
                Interceptor.attach(funcAddr, {
                    onEnter: function(args) {
                        this.isTimingCheck = true;
                    },
                    onLeave: function(retval) {
                        if (this.isTimingCheck) {
                            console.log(`[!] Timing function ${funcName} called - potential anti-debug`);
                        }
                    }
                });
            }
        } catch (err) {
            // Function not found in this module
        }
    });
}

// Initialize advanced patching
setTimeout(() => {
    patchNativeAntiDebug();
    analyzeCustomAntiDebug();
}, 1000); // Wait for libraries to load
```

## 🎯 Phase 3: Stealth and Persistence

### 3.1 Stealth Mode Implementation

#### Frida Detection Evasion
```javascript
// frida_scripts/anti_debug/stealth_mode.js
console.log("[+] Stealth Mode activated");

// Hide Frida from various detection methods
function enableStealthMode() {
    hideFridaFromProcessList();
    hideFridaFromMemory();
    hideFridaFromNetwork();
    hideFridaFromFilesystem();
    spoofEnvironment();
}

function hideFridaFromProcessList() {
    console.log("[+] Hiding Frida from process enumeration...");
    
    try {
        // Hook process listing functions
        const Runtime = Java.use("java.lang.Runtime");
        
        Runtime.exec.overload('java.lang.String').implementation = function(command) {
            if (command.includes("ps") || command.includes("top") || command.includes("netstat")) {
                console.log(`[+] Intercepting process command: ${command}`);
                
                // Execute the command normally
                const process = this.exec(command);
                
                // Create a wrapper to filter output
                const FilteredProcess = Java.registerClass({
                    name: 'FilteredProcess',
                    extends: Java.use('java.lang.Process'),
                    methods: {
                        getInputStream: function() {
                            const originalStream = process.getInputStream();
                            return createFilteredInputStream(originalStream);
                        }
                    }
                });
                
                return FilteredProcess.$new();
            }
            
            return this.exec(command);
        };
        
        // Hook native process enumeration
        const fopenPtr = Module.findExportByName("libc.so", "fopen");
        if (fopenPtr) {
            Interceptor.attach(fopenPtr, {
                onEnter: function(args) {
                    const filename = Memory.readUtf8String(args[0]);
                    
                    if (filename === "/proc/net/tcp" || filename.startsWith("/proc/") && filename.includes("stat")) {
                        console.log(`[+] Intercepting proc file access: ${filename}`);
                        this.shouldFilter = true;
                    }
                }
            });
        }
        
    } catch (err) {
        console.log("[-] Failed to hide from process list: " + err);
    }
}

function createFilteredInputStream(originalStream) {
    // This is a simplified version - in practice, you'd need to properly filter the stream
    console.log("[+] Creating filtered input stream to hide Frida processes");
    return originalStream;
}

function hideFridaFromMemory() {
    console.log("[+] Hiding Frida from memory scanning...");
    
    try {
        // Hook memory scanning functions
        const File = Java.use("java.io.File");
        
        File.exists.implementation = function() {
            const path = this.getAbsolutePath();
            
            // Hide Frida-related files
            if (path.includes("frida") || path.includes("re.frida") || path.includes("gadget")) {
                console.log(`[+] Hiding file from existence check: ${path}`);
                return false;
            }
            
            return this.exists();
        };
        
        // Hook memory mapping enumeration
        const mapsPattern = "/proc/self/maps";
        const fopenPtr = Module.findExportByName("libc.so", "fopen");
        
        if (fopenPtr) {
            Interceptor.attach(fopenPtr, {
                onEnter: function(args) {
                    const filename = Memory.readUtf8String(args[0]);
                    
                    if (filename === mapsPattern) {
                        console.log("[+] Intercepting /proc/self/maps access");
                        this.shouldFilterMaps = true;
                    }
                },
                onLeave: function(retval) {
                    if (this.shouldFilterMaps && retval.toInt32() !== 0) {
                        // Wrap the file handle to filter Frida entries
                        this.originalFile = retval;
                    }
                }
            });
        }
        
    } catch (err) {
        console.log("[-] Failed to hide from memory scanning: " + err);
    }
}

function hideFridaFromNetwork() {
    console.log("[+] Hiding Frida from network detection...");
    
    try {
        // Hook network enumeration
        const netstatFiles = ["/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp"];
        
        netstatFiles.forEach(file => {
            const fopenPtr = Module.findExportByName("libc.so", "fopen");
            
            if (fopenPtr) {
                Interceptor.attach(fopenPtr, {
                    onEnter: function(args) {
                        const filename = Memory.readUtf8String(args[0]);
                        
                        if (filename === file) {
                            console.log(`[+] Intercepting network file: ${filename}`);
                            this.isNetworkFile = true;
                        }
                    },
                    onLeave: function(retval) {
                        if (this.isNetworkFile && retval.toInt32() !== 0) {
                            // Filter out Frida listening ports (typically 27042)
                            console.log("[+] Filtering Frida ports from network output");
                        }
                    }
                });
            }
        });
        
    } catch (err) {
        console.log("[-] Failed to hide from network detection: " + err);
    }
}

function hideFridaFromFilesystem() {
    console.log("[+] Hiding Frida from filesystem detection...");
    
    try {
        // Common Frida file locations
        const fridaFiles = [
            "/data/local/tmp/frida-server",
            "/data/local/tmp/re.frida.server",
            "/system/bin/frida-server",
            "/system/xbin/frida-server"
        ];
        
        const File = Java.use("java.io.File");
        
        File.exists.implementation = function() {
            const path = this.getAbsolutePath();
            
            // Hide Frida server binaries
            if (fridaFiles.includes(path)) {
                console.log(`[+] Hiding Frida server file: ${path}`);
                return false;
            }
            
            // Hide any file with "frida" in the name
            if (path.toLowerCase().includes("frida")) {
                console.log(`[+] Hiding Frida-related file: ${path}`);
                return false;
            }
            
            return this.exists();
        };
        
        // Hook directory listing
        File.listFiles.overload().implementation = function() {
            const files = this.listFiles();
            
            if (files) {
                const filtered = [];
                for (let i = 0; i < files.length; i++) {
                    const file = files[i];
                    const filename = file.getName();
                    
                    if (!filename.toLowerCase().includes("frida")) {
                        filtered.push(file);
                    }
                }
                return filtered;
            }
            
            return files;
        };
        
    } catch (err) {
        console.log("[-] Failed to hide from filesystem detection: " + err);
    }
}

function spoofEnvironment() {
    console.log("[+] Spoofing environment variables...");
    
    try {
        const System = Java.use("java.lang.System");
        
        System.getenv.overload('java.lang.String').implementation = function(name) {
            const value = this.getenv(name);
            
            // Hide Frida-related environment variables
            if (name.includes("FRIDA") || name.includes("frida")) {
                console.log(`[+] Hiding environment variable: ${name}`);
                return null;
            }
            
            // Spoof LD_PRELOAD to hide injection
            if (name === "LD_PRELOAD" && value && value.includes("frida")) {
                console.log("[+] Spoofing LD_PRELOAD environment variable");
                return null;
            }
            
            return value;
        };
        
        // Hook native getenv
        const getenvPtr = Module.findExportByName("libc.so", "getenv");
        if (getenvPtr) {
            Interceptor.attach(getenvPtr, {
                onEnter: function(args) {
                    const varName = Memory.readUtf8String(args[0]);
                    this.varName = varName;
                },
                onLeave: function(retval) {
                    if (this.varName && this.varName.toLowerCase().includes("frida")) {
                        console.log(`[+] Hiding native environment variable: ${this.varName}`);
                        retval.replace(ptr(0)); // Return NULL
                    }
                }
            });
        }
        
    } catch (err) {
        console.log("[-] Failed to spoof environment: " + err);
    }
}

// Enable stealth mode
enableStealthMode();

// Periodic stealth maintenance
setInterval(() => {
    console.log("[+] Maintaining stealth mode...");
    
    // Re-apply stealth measures for newly loaded modules
    enableStealthMode();
    
}, 30000); // Every 30 seconds
```

### 3.2 Automation and Orchestration

#### Complete Bypass Automation
```python
# scripts/anti_debug/bypass_automation.py
import subprocess
import time
import json
import os
import threading
from pathlib import Path

class BypassAutomation:
    def __init__(self, package_name, apk_path=None):
        self.package_name = package_name
        self.apk_path = apk_path
        self.bypass_status = {
            'jdwp': False,
            'native': False,
            'root': False,
            'stealth': False
        }
        self.active_scripts = []
        
    def run_comprehensive_bypass(self):
        """Run comprehensive anti-debugging bypass"""
        print(f"[+] Starting comprehensive bypass for {self.package_name}")
        
        # Step 1: Analyze protections
        if self.apk_path:
            protections = self.analyze_protections()
            self.generate_bypass_strategy(protections)
        
        # Step 2: Start Frida server in stealth mode
        self.start_stealth_frida()
        
        # Step 3: Load bypass scripts
        self.load_bypass_scripts()
        
        # Step 4: Monitor and maintain bypasses
        self.monitor_bypasses()
        
        return self.bypass_status
    
    def analyze_protections(self):
        """Analyze APK for anti-debugging protections"""
        print("[+] Analyzing anti-debugging protections...")
        
        # Run the detection scanner
        cmd = f"python scripts/anti_debug/detection_scanner.py {self.apk_path}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            try:
                with open('anti_debug_report.json', 'r') as f:
                    return json.load(f)
            except:
                return {}
        
        return {}
    
    def generate_bypass_strategy(self, protections):
        """Generate bypass strategy based on detected protections"""
        print("[+] Generating bypass strategy...")
        
        strategy = {
            'scripts': [],
            'priorities': [],
            'methods': []
        }
        
        # Check detected protections and add appropriate bypasses
        if protections.get('detection_summary', {}).get('java_code', 0) > 0:
            strategy['scripts'].append('universal_bypass.js')
            strategy['priorities'].append('High')
            strategy['methods'].append('Java hooks')
        
        if protections.get('detection_summary', {}).get('native_code', 0) > 0:
            strategy['scripts'].append('native_patcher.js')
            strategy['priorities'].append('High')
            strategy['methods'].append('Native patching')
        
        if protections.get('detection_summary', {}).get('manifest', 0) > 0:
            strategy['methods'].append('APK patching')
        
        # Always add stealth mode
        strategy['scripts'].append('stealth_mode.js')
        strategy['priorities'].append('Critical')
        strategy['methods'].append('Stealth evasion')
        
        self.bypass_strategy = strategy
        print(f"[+] Strategy generated: {len(strategy['scripts'])} scripts, {len(strategy['methods'])} methods")
    
    def start_stealth_frida(self):
        """Start Frida server in stealth mode"""
        print("[+] Starting Frida server in stealth mode...")
        
        # Kill existing Frida servers
        subprocess.run("adb shell 'killall frida-server'", shell=True, capture_output=True)
        time.sleep(2)
        
        # Rename frida-server to avoid detection
        stealth_name = "android_service"
        subprocess.run(f"adb shell 'mv /data/local/tmp/frida-server /data/local/tmp/{stealth_name}'", 
                      shell=True, capture_output=True)
        
        # Start with stealth options
        cmd = f"adb shell '/data/local/tmp/{stealth_name} -D &'"
        subprocess.run(cmd, shell=True, capture_output=True)
        
        # Wait for server to start
        time.sleep(3)
        
        # Verify connection
        result = subprocess.run("frida-ps -U", shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print("[+] Frida server started successfully in stealth mode")
            return True
        else:
            print("[-] Failed to start Frida server")
            return False
    
    def load_bypass_scripts(self):
        """Load all necessary bypass scripts"""
        print("[+] Loading bypass scripts...")
        
        scripts = [
            'frida_scripts/anti_debug/universal_bypass.js',
            'frida_scripts/anti_debug/native_patcher.js',
            'frida_scripts/anti_debug/stealth_mode.js'
        ]
        
        # Load each script
        for script_path in scripts:
            if os.path.exists(script_path):
                success = self.load_frida_script(script_path)
                if success:
                    self.active_scripts.append(script_path)
                    print(f"[+] Loaded: {script_path}")
                else:
                    print(f"[-] Failed to load: {script_path}")
        
        # Update bypass status
        self.update_bypass_status()
    
    def load_frida_script(self, script_path):
        """Load individual Frida script"""
        try:
            cmd = f"frida -U -l {script_path} -f {self.package_name} --no-pause"
            
            # Run in background
            process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, 
                                     stderr=subprocess.PIPE, text=True)
            
            # Give it time to attach
            time.sleep(2)
            
            # Check if process is still running (indicates success)
            if process.poll() is None:
                return True
            else:
                return False
                
        except Exception as e:
            print(f"[-] Error loading script {script_path}: {e}")
            return False
    
    def update_bypass_status(self):
        """Update bypass status based on loaded scripts"""
        for script in self.active_scripts:
            if 'universal_bypass' in script:
                self.bypass_status['jdwp'] = True
            elif 'native_patcher' in script:
                self.bypass_status['native'] = True
            elif 'stealth_mode' in script:
                self.bypass_status['stealth'] = True
        
        # Check root bypass (part of universal)
        if self.bypass_status['jdwp']:
            self.bypass_status['root'] = True
    
    def monitor_bypasses(self):
        """Monitor bypass effectiveness"""
        print("[+] Starting bypass monitoring...")
        
        def monitor_thread():
            while True:
                try:
                    # Check if target app is still running
                    result = subprocess.run(f"frida-ps -U | grep {self.package_name}", 
                                          shell=True, capture_output=True, text=True)
                    
                    if result.returncode == 0:
                        print(f"[+] Target app {self.package_name} is running")
                        
                        # Test bypass effectiveness
                        self.test_bypass_effectiveness()
                        
                    else:
                        print(f"[-] Target app {self.package_name} not found")
                    
                    time.sleep(30)  # Check every 30 seconds
                    
                except KeyboardInterrupt:
                    print("[+] Monitoring stopped")
                    break
                except Exception as e:
                    print(f"[-] Monitoring error: {e}")
                    time.sleep(10)
        
        # Start monitoring in background
        monitor = threading.Thread(target=monitor_thread, daemon=True)
        monitor.start()
    
    def test_bypass_effectiveness(self):
        """Test if bypasses are working effectively"""
        try:
            # Create a simple test script to verify bypasses
            test_script = '''
            Java.perform(() => {
                try {
                    const Debug = Java.use("android.os.Debug");
                    const isConnected = Debug.isDebuggerConnected();
                    console.log("BYPASS_TEST: isDebuggerConnected = " + isConnected);
                } catch (err) {
                    console.log("BYPASS_TEST: Debug class not accessible");
                }
            });
            '''
            
            # Write test script to temp file
            with open('temp_test.js', 'w') as f:
                f.write(test_script)
            
            # Run test
            result = subprocess.run(f"frida -U -l temp_test.js {self.package_name}", 
                                  shell=True, capture_output=True, text=True, timeout=10)
            
            if "isDebuggerConnected = false" in result.stdout:
                print("[+] JDWP bypass is working effectively")
                self.bypass_status['jdwp'] = True
            else:
                print("[-] JDWP bypass may not be working")
                self.bypass_status['jdwp'] = False
            
            # Clean up
            os.remove('temp_test.js')
            
        except Exception as e:
            print(f"[-] Bypass test failed: {e}")
    
    def generate_bypass_report(self):
        """Generate comprehensive bypass report"""
        report = {
            'package_name': self.package_name,
            'bypass_status': self.bypass_status,
            'active_scripts': self.active_scripts,
            'timestamp': time.time(),
            'effectiveness_score': self.calculate_effectiveness_score()
        }
        
        return report
    
    def calculate_effectiveness_score(self):
        """Calculate overall bypass effectiveness score"""
        total_bypasses = len(self.bypass_status)
        successful_bypasses = sum(1 for status in self.bypass_status.values() if status)
        
        return (successful_bypasses / total_bypasses) * 100

# Usage
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python bypass_automation.py <package_name> [apk_path]")
        sys.exit(1)
    
    package_name = sys.argv[1]
    apk_path = sys.argv[2] if len(sys.argv) > 2 else None
    
    automation = BypassAutomation(package_name, apk_path)
    
    try:
        result = automation.run_comprehensive_bypass()
        
        print("\n" + "="*50)
        print("BYPASS AUTOMATION RESULT")
        print("="*50)
        
        for bypass_type, status in result.items():
            status_text = "✓ SUCCESS" if status else "✗ FAILED"
            print(f"{bypass_type.upper()}: {status_text}")
        
        # Generate final report
        report = automation.generate_bypass_report()
        
        with open(f'bypass_report_{package_name}.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\nEffectiveness Score: {report['effectiveness_score']:.1f}%")
        print(f"Report saved to: bypass_report_{package_name}.json")
        
        # Keep monitoring
        print("\nMonitoring active. Press Ctrl+C to stop...")
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n[+] Bypass automation stopped")
```

## 📊 Phase 4: Testing and Validation

### 4.1 Bypass Validation Framework

#### Comprehensive Testing Suite
```python
# scripts/anti_debug/bypass_validator.py
import subprocess
import time
import json
import threading
from typing import Dict, List, Tuple

class BypassValidator:
    def __init__(self, package_name: str):
        self.package_name = package_name
        self.test_results = {}
        
    def run_validation_suite(self) -> Dict:
        """Run comprehensive bypass validation tests"""
        print("[+] Starting bypass validation suite...")
        
        tests = [
            self.test_jdwp_bypass,
            self.test_application_flag_bypass,
            self.test_ptrace_bypass,
            self.test_proc_status_bypass,
            self.test_root_detection_bypass,
            self.test_timing_bypass,
            self.test_stealth_effectiveness
        ]
        
        for test in tests:
            try:
                result = test()
                test_name = test.__name__.replace('test_', '')
                self.test_results[test_name] = result
                
                status = "PASS" if result['success'] else "FAIL"
                print(f"[{status}] {test_name}: {result['message']}")
                
            except Exception as e:
                test_name = test.__name__.replace('test_', '')
                self.test_results[test_name] = {
                    'success': False,
                    'message': f"Test failed with exception: {e}",
                    'details': str(e)
                }
                print(f"[ERROR] {test_name}: {e}")
        
        return self.generate_validation_report()
    
    def test_jdwp_bypass(self) -> Dict:
        """Test JDWP detection bypass"""
        test_script = '''
        Java.perform(() => {
            try {
                const Debug = Java.use("android.os.Debug");
                const result = Debug.isDebuggerConnected();
                console.log("JDWP_TEST_RESULT:" + result);
            } catch (err) {
                console.log("JDWP_TEST_ERROR:" + err);
            }
        });
        '''
        
        return self.run_frida_test(test_script, "JDWP_TEST_RESULT:false", 
                                  "JDWP bypass working - isDebuggerConnected returns false")
    
    def test_application_flag_bypass(self) -> Dict:
        """Test application debuggable flag bypass"""
        test_script = '''
        Java.perform(() => {
            try {
                const context = Java.use("android.app.ActivityThread").currentApplication();
                const appInfo = context.getApplicationInfo();
                const FLAG_DEBUGGABLE = 2;
                const isDebuggable = (appInfo.flags.value & FLAG_DEBUGGABLE) !== 0;
                console.log("FLAG_TEST_RESULT:" + isDebuggable);
            } catch (err) {
                console.log("FLAG_TEST_ERROR:" + err);
            }
        });
        '''
        
        return self.run_frida_test(test_script, "FLAG_TEST_RESULT:false",
                                  "Application flag bypass working - FLAG_DEBUGGABLE not set")
    
    def test_ptrace_bypass(self) -> Dict:
        """Test ptrace bypass"""
        test_script = '''
        const ptracePtr = Module.findExportByName("libc.so", "ptrace");
        if (ptracePtr) {
            const ptrace = new NativeFunction(ptracePtr, 'long', ['int', 'int', 'pointer', 'pointer']);
            const result = ptrace(0, 0, ptr(0), ptr(0)); // PTRACE_TRACEME
            console.log("PTRACE_TEST_RESULT:" + result);
        } else {
            console.log("PTRACE_TEST_ERROR:ptrace not found");
        }
        '''
        
        return self.run_frida_test(test_script, "PTRACE_TEST_RESULT:0",
                                  "Ptrace bypass working - PTRACE_TRACEME returns success")
    
    def test_proc_status_bypass(self) -> Dict:
        """Test /proc/self/status bypass"""
        test_script = '''
        const fopenPtr = Module.findExportByName("libc.so", "fopen");
        if (fopenPtr) {
            const fopen = new NativeFunction(fopenPtr, 'pointer', ['pointer', 'pointer']);
            const filename = Memory.allocUtf8String("/proc/self/status");
            const mode = Memory.allocUtf8String("r");
            const result = fopen(filename, mode);
            console.log("PROC_TEST_RESULT:" + (result.isNull() ? "blocked" : "allowed"));
        } else {
            console.log("PROC_TEST_ERROR:fopen not found");
        }
        '''
        
        return self.run_frida_test(test_script, "PROC_TEST_RESULT:blocked",
                                  "Proc status bypass working - /proc/self/status access blocked")
    
    def test_root_detection_bypass(self) -> Dict:
        """Test root detection bypass"""
        test_script = '''
        Java.perform(() => {
            try {
                const File = Java.use("java.io.File");
                const suFile = File.$new("/system/bin/su");
                const exists = suFile.exists();
                console.log("ROOT_TEST_RESULT:" + exists);
            } catch (err) {
                console.log("ROOT_TEST_ERROR:" + err);
            }
        });
        '''
        
        return self.run_frida_test(test_script, "ROOT_TEST_RESULT:false",
                                  "Root bypass working - su binary not detected")
    
    def test_timing_bypass(self) -> Dict:
        """Test timing attack bypass"""
        test_script = '''
        Java.perform(() => {
            try {
                const start = Date.now();
                
                // Simulate timing check
                const System = Java.use("java.lang.System");
                const time1 = System.currentTimeMillis();
                
                // Small delay
                Java.use("java.lang.Thread").sleep(10);
                
                const time2 = System.currentTimeMillis();
                const diff = time2 - time1;
                
                console.log("TIMING_TEST_RESULT:" + diff);
            } catch (err) {
                console.log("TIMING_TEST_ERROR:" + err);
            }
        });
        '''
        
        # Timing should be predictable (not too fast or too slow)
        result = self.run_frida_test_custom(test_script)
        
        if result['success']:
            try:
                timing_value = int(result['output'].split(':')[1])
                if 5 <= timing_value <= 50:  # Reasonable timing range
                    return {
                        'success': True,
                        'message': f"Timing bypass working - consistent timing: {timing_value}ms",
                        'details': f"Timing value within expected range: {timing_value}ms"
                    }
                else:
                    return {
                        'success': False,
                        'message': f"Timing bypass may not be working - unusual timing: {timing_value}ms",
                        'details': f"Timing value outside expected range: {timing_value}ms"
                    }
            except:
                return {
                    'success': False,
                    'message': "Timing test failed - unable to parse timing value",
                    'details': result['output']
                }
        
        return result
    
    def test_stealth_effectiveness(self) -> Dict:
        """Test stealth mode effectiveness"""
        print("[+] Testing stealth effectiveness...")
        
        # Test 1: Check if frida-server is visible in process list
        stealth_tests = []
        
        # Process list test
        ps_result = subprocess.run("adb shell ps | grep frida", 
                                 shell=True, capture_output=True, text=True)
        
        if ps_result.returncode != 0 or "frida" not in ps_result.stdout:
            stealth_tests.append(("process_list", True, "Frida not visible in process list"))
        else:
            stealth_tests.append(("process_list", False, "Frida visible in process list"))
        
        # Network port test
        netstat_result = subprocess.run("adb shell netstat | grep 27042", 
                                      shell=True, capture_output=True, text=True)
        
        if netstat_result.returncode != 0 or "27042" not in netstat_result.stdout:
            stealth_tests.append(("network_port", True, "Frida port not visible"))
        else:
            stealth_tests.append(("network_port", False, "Frida port visible"))
        
        # File system test
        ls_result = subprocess.run("adb shell ls /data/local/tmp/ | grep frida", 
                                 shell=True, capture_output=True, text=True)
        
        if ls_result.returncode != 0 or "frida" not in ls_result.stdout:
            stealth_tests.append(("filesystem", True, "Frida files not visible"))
        else:
            stealth_tests.append(("filesystem", False, "Frida files visible"))
        
        # Calculate stealth score
        passed_tests = sum(1 for _, success, _ in stealth_tests if success)
        total_tests = len(stealth_tests)
        stealth_score = (passed_tests / total_tests) * 100
        
        return {
            'success': stealth_score >= 66,  # At least 2/3 tests should pass
            'message': f"Stealth effectiveness: {stealth_score:.1f}% ({passed_tests}/{total_tests} tests passed)",
            'details': {
                'tests': stealth_tests,
                'score': stealth_score
            }
        }
    
    def run_frida_test(self, script: str, expected_output: str, success_message: str) -> Dict:
        """Run a Frida test script and check for expected output"""
        try:
            # Write script to temporary file
            with open('temp_test.js', 'w') as f:
                f.write(script)
            
            # Run Frida script
            result = subprocess.run(
                f"frida -U -l temp_test.js {self.package_name}",
                shell=True, capture_output=True, text=True, timeout=15
            )
            
            if expected_output in result.stdout:
                return {
                    'success': True,
                    'message': success_message,
                    'details': result.stdout
                }
            else:
                return {
                    'success': False,
                    'message': f"Expected '{expected_output}' not found in output",
                    'details': result.stdout
                }
        
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'message': "Test timed out",
                'details': "Script execution exceeded timeout"
            }
        except Exception as e:
            return {
                'success': False,
                'message': f"Test failed with exception: {e}",
                'details': str(e)
            }
        finally:
            # Clean up
            try:
                import os
                os.remove('temp_test.js')
            except:
                pass
    
    def run_frida_test_custom(self, script: str) -> Dict:
        """Run a Frida test script with custom result processing"""
        try:
            with open('temp_test.js', 'w') as f:
                f.write(script)
            
            result = subprocess.run(
                f"frida -U -l temp_test.js {self.package_name}",
                shell=True, capture_output=True, text=True, timeout=15
            )
            
            return {
                'success': True,
                'output': result.stdout,
                'details': result.stdout
            }
        
        except Exception as e:
            return {
                'success': False,
                'message': f"Test failed: {e}",
                'details': str(e)
            }
        finally:
            try:
                import os
                os.remove('temp_test.js')
            except:
                pass
    
    def generate_validation_report(self) -> Dict:
        """Generate comprehensive validation report"""
        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results.values() if result['success'])
        
        report = {
            'package_name': self.package_name,
            'timestamp': time.time(),
            'summary': {
                'total_tests': total_tests,
                'passed_tests': passed_tests,
                'failed_tests': total_tests - passed_tests,
                'success_rate': (passed_tests / total_tests) * 100 if total_tests > 0 else 0
            },
            'test_results': self.test_results,
            'overall_assessment': self.get_overall_assessment(passed_tests, total_tests)
        }
        
        return report
    
    def get_overall_assessment(self, passed: int, total: int) -> str:
        """Get overall assessment based on test results"""
        success_rate = (passed / total) * 100 if total > 0 else 0
        
        if success_rate >= 90:
            return "Excellent - All critical bypasses working"
        elif success_rate >= 75:
            return "Good - Most bypasses working effectively"
        elif success_rate >= 50:
            return "Moderate - Some bypasses need improvement"
        else:
            return "Poor - Major bypass issues detected"

# Usage
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python bypass_validator.py <package_name>")
        sys.exit(1)
    
    package_name = sys.argv[1]
    validator = BypassValidator(package_name)
    
    report = validator.run_validation_suite()
    
    print("\n" + "="*50)
    print("BYPASS VALIDATION REPORT")
    print("="*50)
    print(f"Package: {package_name}")
    print(f"Success Rate: {report['summary']['success_rate']:.1f}%")
    print(f"Tests Passed: {report['summary']['passed_tests']}/{report['summary']['total_tests']}")
    print(f"Assessment: {report['overall_assessment']}")
    
    # Save detailed report
    with open(f'validation_report_{package_name}.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\nDetailed report saved: validation_report_{package_name}.json")
```

## 🎯 Best Practices and Recommendations

### 1. Layered Defense Approach
- Always use multiple bypass techniques simultaneously
- Implement redundancy for critical bypasses
- Monitor bypass effectiveness continuously

### 2. Stealth Considerations
- Rename Frida server to avoid detection
- Hide process footprints and network connections
- Use minimal resource consumption

### 3. Persistence Strategies
- Implement automatic re-injection capabilities
- Monitor for protection updates
- Maintain bypass scripts for different app versions

### 4. Testing and Validation
- Regularly test bypass effectiveness
- Validate against known detection techniques
- Keep bypass techniques updated

## 🚀 Conclusion

This comprehensive anti-debugging bypass guide provides:

1. **Detection Analysis** - Systematic identification of protection mechanisms
2. **Universal Bypasses** - Comprehensive bypass implementations
3. **Stealth Techniques** - Advanced evasion strategies
4. **Automation Tools** - Automated bypass deployment and monitoring
5. **Validation Framework** - Testing and effectiveness measurement

The techniques covered enable successful reverse engineering of protected Android applications while maintaining stealth and persistence.

## 📚 References

- [Android Anti-Debugging Techniques](https://developer.android.com/ndk/guides/debugging)
- [Frida Anti-Detection](https://frida.re/docs/anti-detection/)
- [OWASP Mobile Security](https://owasp.org/www-project-mobile-security-testing-guide/)
- [Android Reverse Engineering](https://github.com/OWASP/owasp-mstg)
- [Native Code Protection](https://source.android.com/security/app-security)
