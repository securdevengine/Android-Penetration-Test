/*
 * Universal Anti-Debug Bypass for Android
 * 
 * This comprehensive Frida script bypasses various anti-debugging and anti-tampering
 * protections commonly found in Android applications.
 * 
 * Bypasses:
 * - JDWP (Java Debug Wire Protocol) detection
 * - Application debuggable flag checks
 * - Ptrace-based detection
 * - /proc/self/status TracerPid checks
 * - Root detection mechanisms
 * - Hook detection techniques
 * - Timing-based detection
 * - Reflection-based detection
 */

console.log("[+] Universal Anti-Debug Bypass Framework loaded");

Java.perform(function() {
    console.log("[+] Initializing anti-debug bypass modules...");
    
    // Initialize bypass modules
    bypassJDWPDetection();
    bypassApplicationFlags();
    bypassNativeDetection();
    bypassRootDetection();
    bypassHookDetection();
    bypassTimingDetection();
    bypassReflectionDetection();
    bypassEmulatorDetection();
    
    console.log("[+] All anti-debug bypass modules activated");
});

function bypassJDWPDetection() {
    console.log("[+] Loading JDWP detection bypass...");
    
    try {
        // Bypass Debug.isDebuggerConnected()
        var Debug = Java.use("android.os.Debug");
        Debug.isDebuggerConnected.implementation = function() {
            console.log("[+] Debug.isDebuggerConnected() bypassed - returning false");
            return false;
        };
        
        // Bypass VMDebug.isDebuggerConnected()
        try {
            var VMDebug = Java.use("dalvik.system.VMDebug");
            VMDebug.isDebuggerConnected.implementation = function() {
                console.log("[+] VMDebug.isDebuggerConnected() bypassed - returning false");
                return false;
            };
        } catch (err) {
            console.log("[-] VMDebug not available: " + err);
        }
        
        // Bypass JDWP via System properties
        var System = Java.use("java.lang.System");
        System.getProperty.implementation = function(key) {
            var result = this.getProperty(key);
            
            if (key === "java.vm.name" && result && result.toLowerCase().includes("debug")) {
                console.log("[+] Spoofing java.vm.name system property");
                return "ART";
            }
            
            if (key === "ro.debuggable" && result === "1") {
                console.log("[+] Spoofing ro.debuggable system property");
                return "0";
            }
            
            if (key === "ro.secure" && result === "0") {
                console.log("[+] Spoofing ro.secure system property");
                return "1";
            }
            
            return result;
        };
        
        console.log("[+] JDWP detection bypass installed");
        
    } catch (err) {
        console.log("[-] Failed to install JDWP bypass: " + err);
    }
}

function bypassApplicationFlags() {
    console.log("[+] Loading application flags bypass...");
    
    try {
        // Bypass ApplicationInfo.FLAG_DEBUGGABLE check
        var ApplicationInfo = Java.use("android.content.pm.ApplicationInfo");
        var FLAG_DEBUGGABLE = 2;
        
        // Hook Context.getApplicationInfo()
        var ContextWrapper = Java.use("android.content.ContextWrapper");
        ContextWrapper.getApplicationInfo.implementation = function() {
            var appInfo = this.getApplicationInfo();
            
            if (appInfo.flags.value & FLAG_DEBUGGABLE) {
                console.log("[+] Removing FLAG_DEBUGGABLE from ApplicationInfo");
                appInfo.flags.value = appInfo.flags.value & ~FLAG_DEBUGGABLE;
            }
            
            return appInfo;
        };
        
        // Hook PackageManager.getApplicationInfo()
        try {
            var PackageManager = Java.use("android.content.pm.PackageManager");
            PackageManager.getApplicationInfo.overload('java.lang.String', 'int').implementation = function(packageName, flags) {
                var appInfo = this.getApplicationInfo(packageName, flags);
                
                if (appInfo.flags.value & FLAG_DEBUGGABLE) {
                    console.log("[+] Removing FLAG_DEBUGGABLE from PackageManager query");
                    appInfo.flags.value = appInfo.flags.value & ~FLAG_DEBUGGABLE;
                }
                
                return appInfo;
            };
        } catch (err) {
            console.log("[-] Failed to hook PackageManager.getApplicationInfo: " + err);
        }
        
        console.log("[+] Application flags bypass installed");
        
    } catch (err) {
        console.log("[-] Failed to install application flags bypass: " + err);
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
        var ptracePtr = Module.findExportByName("libc.so", "ptrace");
        if (ptracePtr) {
            Interceptor.replace(ptracePtr, new NativeCallback(function(request, pid, addr, data) {
                console.log("[+] ptrace() call intercepted - Request: " + request + ", PID: " + pid);
                
                // PTRACE_TRACEME = 0
                if (request === 0) {
                    console.log("[+] PTRACE_TRACEME blocked - returning success");
                    return 0;
                }
                
                // For other ptrace operations, return success without actually tracing
                if (request === 1) { // PTRACE_PEEKTEXT
                    console.log("[+] PTRACE_PEEKTEXT blocked");
                    return 0;
                }
                
                if (request === 2) { // PTRACE_PEEKDATA
                    console.log("[+] PTRACE_PEEKDATA blocked");
                    return 0;
                }
                
                // Default: allow other operations but log them
                console.log("[+] ptrace operation " + request + " allowed");
                return 0; // Fake success
                
            }, 'long', ['int', 'int', 'pointer', 'pointer']));
            
            console.log("[+] ptrace bypass installed");
        }
    } catch (err) {
        console.log("[-] Failed to hook ptrace: " + err);
    }
}

function bypassProcStatusDetection() {
    try {
        // Hook fopen to intercept /proc/self/status reads
        var fopenPtr = Module.findExportByName("libc.so", "fopen");
        if (fopenPtr) {
            Interceptor.attach(fopenPtr, {
                onEnter: function(args) {
                    var filename = Memory.readUtf8String(args[0]);
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
        
        // Hook open syscall
        var openPtr = Module.findExportByName("libc.so", "open");
        if (openPtr) {
            Interceptor.attach(openPtr, {
                onEnter: function(args) {
                    var filename = Memory.readUtf8String(args[0]);
                    
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
        var readPtr = Module.findExportByName("libc.so", "read");
        if (readPtr) {
            Interceptor.attach(readPtr, {
                onEnter: function(args) {
                    this.fd = args[0].toInt32();
                    this.buffer = args[1];
                    this.count = args[2].toInt32();
                },
                onLeave: function(retval) {
                    if (retval.toInt32() > 0) {
                        try {
                            var content = Memory.readUtf8String(this.buffer, retval.toInt32());
                            
                            if (content.includes("TracerPid:") && !content.includes("TracerPid:\t0")) {
                                console.log("[+] Spoofing TracerPid in /proc/self/status");
                                var spoofed = content.replace(/TracerPid:\s*\d+/, "TracerPid:\t0");
                                Memory.writeUtf8String(this.buffer, spoofed);
                                retval.replace(ptr(spoofed.length));
                            }
                        } catch (e) {
                            // Ignore read errors
                        }
                    }
                }
            });
        }
        
        console.log("[+] /proc/self/status bypass installed");
        
    } catch (err) {
        console.log("[-] Failed to install proc status bypass: " + err);
    }
}

function bypassLibraryDetection() {
    try {
        // Hook dlopen to hide library loading
        var dlopenPtr = Module.findExportByName("libdl.so", "dlopen");
        if (dlopenPtr) {
            Interceptor.attach(dlopenPtr, {
                onEnter: function(args) {
                    var libraryPath = Memory.readUtf8String(args[0]);
                    
                    if (libraryPath && (libraryPath.includes("frida") || 
                                      libraryPath.includes("xposed") || 
                                      libraryPath.includes("substrate"))) {
                        console.log("[+] Hiding library load: " + libraryPath);
                        this.shouldHide = true;
                    }
                },
                onLeave: function(retval) {
                    if (this.shouldHide) {
                        retval.replace(ptr(0)); // Return NULL (library not found)
                    }
                }
            });
        }
        
        // Hook System.loadLibrary
        var System = Java.use("java.lang.System");
        System.loadLibrary.implementation = function(libraryName) {
            console.log("[+] System.loadLibrary called: " + libraryName);
            
            // Allow normal libraries
            var suspiciousLibs = ["frida", "xposed", "substrate", "cydia"];
            var isSuspicious = suspiciousLibs.some(function(lib) {
                return libraryName.toLowerCase().includes(lib);
            });
            
            if (!isSuspicious) {
                return this.loadLibrary(libraryName);
            } else {
                console.log("[+] Blocking suspicious library: " + libraryName);
                var UnsatisfiedLinkError = Java.use("java.lang.UnsatisfiedLinkError");
                throw UnsatisfiedLinkError.$new("Library not found: " + libraryName);
            }
        };
        
        console.log("[+] Library detection bypass installed");
        
    } catch (err) {
        console.log("[-] Failed to install library detection bypass: " + err);
    }
}

function bypassRootDetection() {
    console.log("[+] Loading root detection bypass...");
    
    try {
        // Common root indicator files
        var rootIndicators = [
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su",
            "/su/bin/su",
            "/system/etc/init.d/99SuperSUDaemon",
            "/dev/com.koushikdutta.superuser.daemon/"
        ];
        
        // Hook File.exists()
        var File = Java.use("java.io.File");
        File.exists.implementation = function() {
            var path = this.getAbsolutePath();
            
            // Check if path is a root indicator
            for (var i = 0; i < rootIndicators.length; i++) {
                if (path.includes(rootIndicators[i])) {
                    console.log("[+] Blocking root file check: " + path);
                    return false;
                }
            }
            
            // Block su binary checks
            if (path.endsWith("/su") || path.includes("busybox")) {
                console.log("[+] Blocking su/busybox check: " + path);
                return false;
            }
            
            return this.exists();
        };
        
        // Hook File.canExecute()
        File.canExecute.implementation = function() {
            var path = this.getAbsolutePath();
            
            if (path.includes("/su") || path.includes("busybox")) {
                console.log("[+] Blocking executable check: " + path);
                return false;
            }
            
            return this.canExecute();
        };
        
        // Hook Runtime.exec() for su command detection
        var Runtime = Java.use("java.lang.Runtime");
        Runtime.exec.overload('java.lang.String').implementation = function(command) {
            if (command.includes("su") || command.includes("which") || command.includes("busybox")) {
                console.log("[+] Blocking suspicious command: " + command);
                var IOException = Java.use("java.io.IOException");
                throw IOException.$new("Command not found: " + command);
            }
            
            return this.exec(command);
        };
        
        Runtime.exec.overload('[Ljava.lang.String;').implementation = function(cmdArray) {
            var command = cmdArray.join(' ');
            
            if (command.includes("su") || command.includes("which") || command.includes("busybox")) {
                console.log("[+] Blocking suspicious command array: " + command);
                var IOException = Java.use("java.io.IOException");
                throw IOException.$new("Command not found");
            }
            
            return this.exec(cmdArray);
        };
        
        // Hook package manager for root app detection
        var PackageManager = Java.use("android.content.pm.PackageManager");
        PackageManager.getInstalledPackages.implementation = function(flags) {
            var packages = this.getInstalledPackages(flags);
            
            // Root-related package names
            var rootPackages = [
                "com.noshufou.android.su",
                "com.thirdparty.superuser",
                "eu.chainfire.supersu",
                "com.koushikdutta.superuser",
                "com.zachspong.temprootremovejb",
                "com.ramdroid.appquarantine",
                "com.topjohnwu.magisk"
            ];
            
            // Filter out root packages
            var filteredPackages = Java.use("java.util.ArrayList").$new();
            var iterator = packages.iterator();
            
            while (iterator.hasNext()) {
                var packageInfo = iterator.next();
                var packageName = packageInfo.packageName.value;
                
                var isRootPackage = rootPackages.some(function(rootPkg) {
                    return packageName.includes(rootPkg);
                });
                
                if (!isRootPackage) {
                    filteredPackages.add(packageInfo);
                } else {
                    console.log("[+] Hiding root package: " + packageName);
                }
            }
            
            return filteredPackages;
        };
        
        // Bypass specific root detection libraries
        bypassRootBeer();
        bypassSafetyNet();
        
        console.log("[+] Root detection bypass installed");
        
    } catch (err) {
        console.log("[-] Failed to install root detection bypass: " + err);
    }
}

function bypassRootBeer() {
    try {
        var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
        
        RootBeer.isRooted.implementation = function() {
            console.log('[+] RootBeer.isRooted() bypassed');
            return false;
        };
        
        RootBeer.isRootedWithoutBusyBoxCheck.implementation = function() {
            console.log('[+] RootBeer.isRootedWithoutBusyBoxCheck() bypassed');
            return false;
        };
        
        console.log("[+] RootBeer bypass installed");
    } catch (err) {
        console.log("[-] RootBeer not found: " + err);
    }
}

function bypassSafetyNet() {
    try {
        // This is a simplified SafetyNet bypass
        // Real SafetyNet bypass is much more complex
        var SafetyNet = Java.use('com.google.android.gms.safetynet.SafetyNet');
        
        SafetyNet.getClient.implementation = function(context) {
            console.log('[+] SafetyNet.getClient() bypassed');
            return null;
        };
        
        console.log("[+] SafetyNet bypass installed");
    } catch (err) {
        console.log("[-] SafetyNet not found: " + err);
    }
}

function bypassHookDetection() {
    console.log("[+] Loading hook detection bypass...");
    
    try {
        // Hide Frida from process lists
        var Runtime = Java.use("java.lang.Runtime");
        Runtime.exec.overload('[Ljava.lang.String;').implementation = function(cmdArray) {
            var command = cmdArray.join(' ');
            
            if (command.includes("ps") || command.includes("netstat") || command.includes("lsof")) {
                console.log("[+] Intercepting process listing command: " + command);
                
                // Execute original command but filter output would require more complex implementation
                // For now, just execute normally
                return this.exec(cmdArray);
            }
            
            return this.exec(cmdArray);
        };
        
        // Hook native library enumeration
        var System = Java.use("java.lang.System");
        System.getProperty.implementation = function(key) {
            var result = this.getProperty(key);
            
            if (key === "java.library.path" && result && result.includes("frida")) {
                console.log("[+] Hiding Frida from library path");
                return result.replace(/[^:]*frida[^:]*/g, "");
            }
            
            return result;
        };
        
        console.log("[+] Hook detection bypass installed");
        
    } catch (err) {
        console.log("[-] Failed to install hook detection bypass: " + err);
    }
}

function bypassTimingDetection() {
    console.log("[+] Loading timing detection bypass...");
    
    try {
        // Hook timing functions to provide consistent results
        var System = Java.use("java.lang.System");
        var baseTime = Date.now();
        var callCount = 0;
        
        System.currentTimeMillis.implementation = function() {
            callCount++;
            // Provide predictable timing increments
            var fakeTime = baseTime + (callCount * 50); // 50ms increments
            console.log("[+] Spoofing System.currentTimeMillis(): " + fakeTime);
            return fakeTime;
        };
        
        System.nanoTime.implementation = function() {
            callCount++;
            var fakeNanoTime = (baseTime + (callCount * 50)) * 1000000;
            console.log("[+] Spoofing System.nanoTime(): " + fakeNanoTime);
            return fakeNanoTime;
        };
        
        // Hook SystemClock
        try {
            var SystemClock = Java.use("android.os.SystemClock");
            
            SystemClock.elapsedRealtime.implementation = function() {
                var elapsed = callCount * 100; // Predictable elapsed time
                console.log("[+] Spoofing SystemClock.elapsedRealtime(): " + elapsed);
                return elapsed;
            };
            
            SystemClock.uptimeMillis.implementation = function() {
                var uptime = baseTime + (callCount * 100);
                console.log("[+] Spoofing SystemClock.uptimeMillis(): " + uptime);
                return uptime;
            };
        } catch (e) {
            console.log("[-] SystemClock hooks failed: " + e);
        }
        
        console.log("[+] Timing detection bypass installed");
        
    } catch (err) {
        console.log("[-] Failed to install timing detection bypass: " + err);
    }
}

function bypassReflectionDetection() {
    console.log("[+] Loading reflection detection bypass...");
    
    try {
        // Hook Class.forName to hide sensitive classes
        var Class = Java.use("java.lang.Class");
        Class.forName.overload('java.lang.String').implementation = function(className) {
            
            // Classes to hide
            var blockedClasses = [
                "dalvik.system.VMDebug",
                "android.os.Debug",
                "de.robv.android.xposed.XposedBridge",
                "com.android.internal.os.RuntimeInit",
                "com.saurik.substrate.MS"
            ];
            
            if (blockedClasses.includes(className)) {
                console.log("[+] Blocking Class.forName for: " + className);
                var ClassNotFoundException = Java.use("java.lang.ClassNotFoundException");
                throw ClassNotFoundException.$new("Class not found: " + className);
            }
            
            return this.forName(className);
        };
        
        // Hook method reflection
        Class.getDeclaredMethod.implementation = function(methodName, parameterTypes) {
            
            // Methods to hide
            var blockedMethods = [
                "isDebuggerConnected",
                "getApplicationInfo",
                "isDebuggingEnabled"
            ];
            
            if (blockedMethods.includes(methodName)) {
                console.log("[+] Blocking getDeclaredMethod for: " + methodName);
                var NoSuchMethodException = Java.use("java.lang.NoSuchMethodException");
                throw NoSuchMethodException.$new("Method not found: " + methodName);
            }
            
            return this.getDeclaredMethod(methodName, parameterTypes);
        };
        
        // Hook field reflection
        Class.getDeclaredField.implementation = function(fieldName) {
            
            var blockedFields = [
                "flags",
                "FLAG_DEBUGGABLE"
            ];
            
            if (blockedFields.includes(fieldName)) {
                console.log("[+] Blocking getDeclaredField for: " + fieldName);
                var NoSuchFieldException = Java.use("java.lang.NoSuchFieldException");
                throw NoSuchFieldException.$new("Field not found: " + fieldName);
            }
            
            return this.getDeclaredField(fieldName);
        };
        
        console.log("[+] Reflection detection bypass installed");
        
    } catch (err) {
        console.log("[-] Failed to install reflection detection bypass: " + err);
    }
}

function bypassEmulatorDetection() {
    console.log("[+] Loading emulator detection bypass...");
    
    try {
        // Hook Build class to spoof device information
        var Build = Java.use("android.os.Build");
        
        // Common emulator indicators in Build fields
        var emulatorIndicators = ["generic", "unknown", "emulator", "android", "google_sdk"];
        
        // We'll hook System.getProperty instead since Build fields are final
        var originalGetProperty = Java.use("java.lang.System").getProperty;
        
        Java.use("java.lang.System").getProperty.implementation = function(key) {
            var result = originalGetProperty.call(this, key);
            
            if (key === "ro.product.model" && result) {
                if (emulatorIndicators.some(indicator => result.toLowerCase().includes(indicator))) {
                    console.log("[+] Spoofing ro.product.model: " + result + " -> Samsung SM-G973F");
                    return "SM-G973F";
                }
            }
            
            if (key === "ro.product.manufacturer" && result) {
                if (result.toLowerCase().includes("generic") || result.toLowerCase().includes("google")) {
                    console.log("[+] Spoofing ro.product.manufacturer: " + result + " -> samsung");
                    return "samsung";
                }
            }
            
            if (key === "ro.hardware" && result) {
                if (emulatorIndicators.some(indicator => result.toLowerCase().includes(indicator))) {
                    console.log("[+] Spoofing ro.hardware: " + result + " -> exynos9820");
                    return "exynos9820";
                }
            }
            
            return result;
        };
        
        console.log("[+] Emulator detection bypass installed");
        
    } catch (err) {
        console.log("[-] Failed to install emulator detection bypass: " + err);
    }
}

console.log("[+] Universal Anti-Debug Bypass Framework ready");
console.log("[+] All anti-debugging protections should now be bypassed");
console.log("[+] Monitor console output for bypass confirmations");

/*
 * Usage Instructions:
 * 
 * 1. Save this script as universal_bypass.js
 * 2. Run with Frida: frida -U -l universal_bypass.js [package_name]
 * 3. Or spawn the app: frida -U -f [package_name] -l universal_bypass.js --no-pause
 * 4. Monitor console output for bypass confirmations
 * 5. The app should now run normally even when debugging tools are attached
 * 
 * Bypass Coverage:
 * - Java-level debug detection (Debug.isDebuggerConnected, etc.)
 * - Native-level ptrace detection
 * - /proc/self/status TracerPid checks
 * - Root detection (file checks, package checks, command execution)
 * - Hook/instrumentation detection
 * - Timing-based detection
 * - Reflection-based detection
 * - Emulator detection
 * 
 * Notes:
 * - Some bypasses may need customization for specific applications
 * - Advanced obfuscated protections may require additional work
 * - This script provides broad coverage but may not catch all detection methods
 * - For persistent bypass, consider using Frida Gadget
 */
