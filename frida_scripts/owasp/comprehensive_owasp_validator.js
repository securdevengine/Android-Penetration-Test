// Comprehensive OWASP Mobile Top 10 Dynamic Validation Script
// This script monitors for OWASP Mobile Top 10 vulnerabilities during runtime

console.log("[*] OWASP Mobile Top 10 Dynamic Validator loaded");

Java.perform(function() {
    console.log("[+] Starting OWASP Mobile Top 10 dynamic validation...");
    
    // M1: Improper Credential Usage - Monitor credential handling
    try {
        var SharedPreferences = Java.use("android.content.SharedPreferences");
        var Editor = Java.use("android.content.SharedPreferences$Editor");
        
        SharedPreferences.getString.overload('java.lang.String', 'java.lang.String').implementation = function(key, defValue) {
            var result = this.getString(key, defValue);
            
            var sensitiveKeys = ["password", "secret", "token", "api_key", "private_key", "auth"];
            for (var i = 0; i < sensitiveKeys.length; i++) {
                if (key.toLowerCase().indexOf(sensitiveKeys[i]) !== -1) {
                    console.log("[M1] [CRITICAL] Sensitive data retrieved from SharedPreferences:");
                    console.log("    Key: " + key);
                    console.log("    Value: " + result);
                    console.log("    Recommendation: Encrypt sensitive data before storage");
                    break;
                }
            }
            
            return result;
        };
        
        Editor.putString.overload('java.lang.String', 'java.lang.String').implementation = function(key, value) {
            var sensitiveKeys = ["password", "secret", "token", "api_key", "private_key", "auth"];
            for (var i = 0; i < sensitiveKeys.length; i++) {
                if (key.toLowerCase().indexOf(sensitiveKeys[i]) !== -1) {
                    console.log("[M1] [CRITICAL] Sensitive data stored in SharedPreferences:");
                    console.log("    Key: " + key);
                    console.log("    Value: " + value);
                    console.log("    Recommendation: Use Android Keystore or encrypt data");
                    break;
                }
            }
            
            return this.putString(key, value);
        };
        
        console.log("[M1] Credential usage monitoring enabled");
    } catch (e) {
        console.log("[-] M1 monitoring failed: " + e);
    }
    
    // M3: Insecure Authentication/Authorization - Monitor auth flows
    try {
        // Monitor login activities
        var Activity = Java.use("android.app.Activity");
        Activity.onCreate.overload('android.os.Bundle').implementation = function(savedInstanceState) {
            var activityName = this.getClass().getName();
            if (activityName.toLowerCase().indexOf("login") !== -1 || 
                activityName.toLowerCase().indexOf("auth") !== -1) {
                console.log("[M3] [INFO] Authentication activity detected: " + activityName);
                
                // Check for debug flags that might bypass auth
                try {
                    var debuggable = this.getApplicationInfo().flags & 2; // ApplicationInfo.FLAG_DEBUGGABLE
                    if (debuggable) {
                        console.log("[M3] [HIGH] Debug mode enabled in authentication context");
                    }
                } catch (e) {}
            }
            
            return this.onCreate(savedInstanceState);
        };
        
        // Monitor HTTP authentication headers
        var HttpURLConnection = Java.use("java.net.HttpURLConnection");
        HttpURLConnection.setRequestProperty.implementation = function(key, value) {
            if (key.toLowerCase() === "authorization" || key.toLowerCase() === "cookie") {
                console.log("[M3] [INFO] Authentication header set:");
                console.log("    Header: " + key);
                console.log("    Value: " + value);
                
                // Check for weak authentication schemes
                if (value.toLowerCase().indexOf("basic") === 0) {
                    console.log("[M3] [MEDIUM] Basic authentication detected - consider stronger methods");
                }
                
                // Check for JWT tokens
                if (value.toLowerCase().indexOf("bearer") === 0) {
                    console.log("[M3] [INFO] JWT Bearer token detected");
                    var token = value.substring(7);
                    var parts = token.split(".");
                    if (parts.length === 3) {
                        try {
                            var header = String.fromBase64(parts[0]);
                            var payload = String.fromBase64(parts[1]);
                            console.log("[M3] [INFO] JWT Header: " + header);
                            console.log("[M3] [INFO] JWT Payload: " + payload);
                            
                            // Check for alg=none
                            if (header.indexOf('"alg":"none"') !== -1) {
                                console.log("[M3] [CRITICAL] JWT with alg=none detected!");
                            }
                        } catch (e) {
                            console.log("[M3] [INFO] Could not decode JWT: " + e);
                        }
                    }
                }
            }
            
            return this.setRequestProperty(key, value);
        };
        
        console.log("[M3] Authentication monitoring enabled");
    } catch (e) {
        console.log("[-] M3 monitoring failed: " + e);
    }
    
    // M4: Insufficient Input/Output Validation - Monitor for injection attacks
    try {
        var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
        
        SQLiteDatabase.execSQL.overload('java.lang.String').implementation = function(sql) {
            console.log("[M4] [INFO] SQL execution detected:");
            console.log("    Query: " + sql);
            
            // Check for potential SQL injection patterns
            var suspiciousPatterns = ["'", "--", ";", "/*", "*/", "xp_", "sp_", "union", "select", "insert", "update", "delete"];
            var sqlLower = sql.toLowerCase();
            
            for (var i = 0; i < suspiciousPatterns.length; i++) {
                if (sqlLower.indexOf(suspiciousPatterns[i]) !== -1 && sqlLower.indexOf("?") === -1) {
                    console.log("[M4] [HIGH] Potential SQL injection vulnerability:");
                    console.log("    Pattern found: " + suspiciousPatterns[i]);
                    console.log("    Recommendation: Use parameterized queries");
                    break;
                }
            }
            
            return this.execSQL(sql);
        };
        
        SQLiteDatabase.rawQuery.overload('java.lang.String', '[Ljava.lang.String;').implementation = function(sql, selectionArgs) {
            console.log("[M4] [INFO] Raw SQL query detected:");
            console.log("    Query: " + sql);
            console.log("    Args: " + (selectionArgs ? selectionArgs.join(", ") : "none"));
            
            if (!selectionArgs && sql.indexOf("'") !== -1) {
                console.log("[M4] [MEDIUM] Raw query without parameters may be vulnerable to injection");
            }
            
            return this.rawQuery(sql, selectionArgs);
        };
        
        console.log("[M4] Input validation monitoring enabled");
    } catch (e) {
        console.log("[-] M4 monitoring failed: " + e);
    }
    
    // M5: Insecure Communication - Monitor network security
    try {
        var URL = Java.use("java.net.URL");
        URL.$init.overload('java.lang.String').implementation = function(spec) {
            if (spec.toLowerCase().indexOf("http://") === 0) {
                console.log("[M5] [HIGH] Insecure HTTP connection detected:");
                console.log("    URL: " + spec);
                console.log("    Recommendation: Use HTTPS instead");
            }
            
            return this.$init(spec);
        };
        
        // Monitor SSL/TLS configurations
        var SSLContext = Java.use("javax.net.ssl.SSLContext");
        SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function(km, tm, random) {
            console.log("[M5] [INFO] SSL Context initialization detected");
            
            if (tm && tm.length > 0) {
                console.log("[M5] [INFO] Custom TrustManager detected - verify implementation");
            }
            
            return this.init(km, tm, random);
        };
        
        console.log("[M5] Communication security monitoring enabled");
    } catch (e) {
        console.log("[-] M5 monitoring failed: " + e);
    }
    
    // M7: Insufficient Binary Protections - Monitor anti-debugging and tampering
    try {
        var Debug = Java.use("android.os.Debug");
        Debug.isDebuggerConnected.implementation = function() {
            var result = this.isDebuggerConnected();
            console.log("[M7] [INFO] Debugger detection check: " + result);
            
            if (result) {
                console.log("[M7] [INFO] Debugger detected by application");
            }
            
            return result;
        };
        
        // Monitor root detection attempts
        var Runtime = Java.use("java.lang.Runtime");
        Runtime.exec.overload('java.lang.String').implementation = function(command) {
            console.log("[M7] [INFO] Runtime command execution:");
            console.log("    Command: " + command);
            
            var rootCommands = ["su", "which su", "/system/bin/su", "/system/xbin/su"];
            for (var i = 0; i < rootCommands.length; i++) {
                if (command.indexOf(rootCommands[i]) !== -1) {
                    console.log("[M7] [INFO] Root detection command detected");
                    break;
                }
            }
            
            return this.exec(command);
        };
        
        console.log("[M7] Binary protection monitoring enabled");
    } catch (e) {
        console.log("[-] M7 monitoring failed: " + e);
    }
    
    // M9: Insecure Data Storage - Monitor file operations
    try {
        var FileOutputStream = Java.use("java.io.FileOutputStream");
        FileOutputStream.$init.overload('java.lang.String').implementation = function(name) {
            console.log("[M9] [INFO] File write operation:");
            console.log("    File: " + name);
            
            // Check if writing to external storage
            if (name.indexOf("/sdcard/") === 0 || name.indexOf("/storage/") === 0 || name.indexOf("external") !== -1) {
                console.log("[M9] [MEDIUM] Writing to external storage detected");
                console.log("    Recommendation: Use internal storage for sensitive data");
            }
            
            // Check for sensitive file extensions
            var sensitiveExts = [".key", ".pem", ".p12", ".jks", ".xml", ".db", ".sqlite"];
            for (var i = 0; i < sensitiveExts.length; i++) {
                if (name.toLowerCase().endsWith(sensitiveExts[i])) {
                    console.log("[M9] [HIGH] Potentially sensitive file being written: " + name);
                    break;
                }
            }
            
            return this.$init(name);
        };
        
        console.log("[M9] Data storage monitoring enabled");
    } catch (e) {
        console.log("[-] M9 monitoring failed: " + e);
    }
    
    // M10: Insufficient Cryptography - Monitor crypto operations
    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        Cipher.getInstance.overload('java.lang.String').implementation = function(transformation) {
            console.log("[M10] [INFO] Cipher instance requested:");
            console.log("    Transformation: " + transformation);
            
            // Check for weak algorithms
            var weakAlgorithms = ["DES", "RC4", "MD5"];
            var transformationUpper = transformation.toUpperCase();
            
            for (var i = 0; i < weakAlgorithms.length; i++) {
                if (transformationUpper.indexOf(weakAlgorithms[i]) !== -1) {
                    console.log("[M10] [HIGH] Weak cryptographic algorithm detected: " + weakAlgorithms[i]);
                    console.log("    Recommendation: Use AES, RSA, or other strong algorithms");
                    break;
                }
            }
            
            // Check for ECB mode
            if (transformationUpper.indexOf("ECB") !== -1) {
                console.log("[M10] [MEDIUM] ECB mode detected - consider using CBC or GCM");
            }
            
            return this.getInstance(transformation);
        };
        
        var MessageDigest = Java.use("java.security.MessageDigest");
        MessageDigest.getInstance.overload('java.lang.String').implementation = function(algorithm) {
            console.log("[M10] [INFO] MessageDigest requested:");
            console.log("    Algorithm: " + algorithm);
            
            if (algorithm.toUpperCase() === "MD5") {
                console.log("[M10] [HIGH] MD5 hash algorithm detected - use SHA-256 or stronger");
            } else if (algorithm.toUpperCase() === "SHA1" || algorithm.toUpperCase() === "SHA-1") {
                console.log("[M10] [MEDIUM] SHA-1 hash algorithm detected - consider SHA-256 or stronger");
            }
            
            return this.getInstance(algorithm);
        };
        
        console.log("[M10] Cryptography monitoring enabled");
    } catch (e) {
        console.log("[-] M10 monitoring failed: " + e);
    }
    
    // Additional monitoring for common Android security issues
    try {
        // Monitor WebView security settings
        var WebView = Java.use("android.webkit.WebView");
        var WebSettings = Java.use("android.webkit.WebSettings");
        
        WebSettings.setJavaScriptEnabled.implementation = function(flag) {
            if (flag) {
                console.log("[M4] [MEDIUM] JavaScript enabled in WebView - ensure proper input validation");
            }
            return this.setJavaScriptEnabled(flag);
        };
        
        WebSettings.setAllowFileAccess.implementation = function(allow) {
            if (allow) {
                console.log("[M9] [HIGH] File access enabled in WebView - potential security risk");
            }
            return this.setAllowFileAccess(allow);
        };
        
        console.log("[+] WebView security monitoring enabled");
    } catch (e) {
        console.log("[-] WebView monitoring failed: " + e);
    }
    
    console.log("[+] OWASP Mobile Top 10 dynamic validation setup complete");
    console.log("[+] Monitor the console for real-time security findings");
});
