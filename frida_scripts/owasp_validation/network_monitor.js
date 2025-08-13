// OWASP M3: Insecure Communication Monitor
// Monitors network communications, SSL/TLS usage, and certificate validation

console.log("[+] OWASP M3 Network Communication Monitor loaded");

Java.perform(function() {
    console.log("[*] Hooking network communication methods...");
    
    // Monitor HTTP connections
    try {
        var URL = Java.use("java.net.URL");
        
        URL.openConnection.overload().implementation = function() {
            var connection = this.openConnection();
            var url = this.toString();
            console.log("[+] URL connection: " + url);
            
            if (url.startsWith('http://')) {
                console.log("[!] Insecure HTTP connection: " + url);
            } else if (url.startsWith('https://')) {
                console.log("[*] Secure HTTPS connection: " + url);
            }
            
            return connection;
        };
        
        console.log("[+] Hooked URL.openConnection");
    } catch (e) {
        console.log("[-] Failed to hook URL: " + e);
    }
    
    // Monitor OkHttp requests
    try {
        var Request = Java.use("okhttp3.Request");
        var RequestBuilder = Java.use("okhttp3.Request$Builder");
        
        RequestBuilder.url.overload('java.lang.String').implementation = function(url) {
            console.log("[+] OkHttp request URL: " + url);
            if (url.startsWith('http://')) {
                console.log("[!] Insecure HTTP request via OkHttp: " + url);
            }
            return this.url(url);
        };
        
        console.log("[+] Hooked OkHttp Request.Builder");
    } catch (e) {
        console.log("[-] Failed to hook OkHttp: " + e);
    }
    
    // Monitor SSL Certificate validation
    try {
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        
        X509TrustManager.checkServerTrusted.implementation = function(certs, authType) {
            console.log("[+] SSL Certificate validation for authType: " + authType);
            console.log("    Certificates: " + certs.length);
            
            for (var i = 0; i < certs.length; i++) {
                var cert = certs[i];
                console.log("    Cert " + i + ": " + cert.getSubjectDN());
            }
            
            // Call original method to maintain security
            return this.checkServerTrusted(certs, authType);
        };
        
        console.log("[+] Hooked X509TrustManager.checkServerTrusted");
    } catch (e) {
        console.log("[-] Failed to hook X509TrustManager: " + e);
    }
    
    // Monitor HostnameVerifier
    try {
        var HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");
        
        HostnameVerifier.verify.implementation = function(hostname, session) {
            console.log("[+] Hostname verification for: " + hostname);
            var result = this.verify(hostname, session);
            console.log("    Verification result: " + result);
            return result;
        };
        
        console.log("[+] Hooked HostnameVerifier.verify");
    } catch (e) {
        console.log("[-] Failed to hook HostnameVerifier: " + e);
    }
    
    // Monitor SSLContext creation
    try {
        var SSLContext = Java.use("javax.net.ssl.SSLContext");
        
        SSLContext.getInstance.overload('java.lang.String').implementation = function(protocol) {
            console.log("[+] SSLContext created with protocol: " + protocol);
            if (protocol === "SSLv3" || protocol === "TLSv1" || protocol === "TLSv1.1") {
                console.log("[!] Weak SSL/TLS protocol used: " + protocol);
            }
            return this.getInstance(protocol);
        };
        
        console.log("[+] Hooked SSLContext.getInstance");
    } catch (e) {
        console.log("[-] Failed to hook SSLContext: " + e);
    }
    
    // Monitor socket connections
    try {
        var Socket = Java.use("java.net.Socket");
        
        Socket.$init.overload('java.lang.String', 'int').implementation = function(host, port) {
            console.log("[+] Socket connection to: " + host + ":" + port);
            return this.$init(host, port);
        };
        
        console.log("[+] Hooked Socket constructor");
    } catch (e) {
        console.log("[-] Failed to hook Socket: " + e);
    }
    
    // Monitor HttpURLConnection
    try {
        var HttpURLConnection = Java.use("java.net.HttpURLConnection");
        
        HttpURLConnection.setRequestMethod.implementation = function(method) {
            console.log("[+] HTTP request method: " + method + " to " + this.getURL());
            return this.setRequestMethod(method);
        };
        
        console.log("[+] Hooked HttpURLConnection.setRequestMethod");
    } catch (e) {
        console.log("[-] Failed to hook HttpURLConnection: " + e);
    }
    
    // Monitor WebView URL loading
    try {
        var WebView = Java.use("android.webkit.WebView");
        
        WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
            console.log("[+] WebView loading URL: " + url);
            if (url.startsWith('http://')) {
                console.log("[!] WebView loading insecure HTTP URL: " + url);
            }
            return this.loadUrl(url);
        };
        
        console.log("[+] Hooked WebView.loadUrl");
    } catch (e) {
        console.log("[-] Failed to hook WebView: " + e);
    }
    
    // Monitor network security config
    try {
        var NetworkSecurityPolicy = Java.use("android.security.NetworkSecurityPolicy");
        
        NetworkSecurityPolicy.getInstance.implementation = function() {
            var policy = this.getInstance();
            console.log("[+] NetworkSecurityPolicy getInstance called");
            return policy;
        };
        
        console.log("[+] Hooked NetworkSecurityPolicy");
    } catch (e) {
        console.log("[-] Failed to hook NetworkSecurityPolicy: " + e);
    }
    
    // Detect custom trust managers
    try {
        var TrustManager = Java.use("javax.net.ssl.TrustManager");
        
        // This will catch custom implementations
        Java.choose("javax.net.ssl.X509TrustManager", {
            onMatch: function(instance) {
                console.log("[+] Found X509TrustManager instance: " + instance.$className);
                if (instance.$className !== "com.android.org.conscrypt.TrustManagerImpl") {
                    console.log("[!] Custom TrustManager detected: " + instance.$className);
                }
            },
            onComplete: function() {}
        });
        
        console.log("[+] Scanning for custom TrustManagers");
    } catch (e) {
        console.log("[-] Failed to scan TrustManagers: " + e);
    }
    
    console.log("[+] Network communication monitoring hooks installed");
});
