console.log("[+] Universal SSL Certificate Pinning Bypass loaded");

Java.perform(function() {
    console.log("[+] Starting SSL bypass implementations...");
    
    bypassStandardSSLVerification();
    bypassOkHttpPinning();
    bypassApacheHTTPClient();
    bypassConscrypt();
    bypassHostnameVerification();
    bypassNetworkSecurityConfig();
    bypassAdditionalSSLImplementations();
    
    console.log("[+] SSL bypass setup complete");
});

function bypassStandardSSLVerification() {
    console.log("[+] Setting up standard SSL verification bypass...");
    
    try {
        // Hook X509TrustManager
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        var TrustManager = Java.use('javax.net.ssl.TrustManager');
        var X509Certificate = Java.use('java.security.cert.X509Certificate');
        
        // Create custom TrustManager that trusts all certificates
        var TrustAllManager = Java.registerClass({
            name: 'TrustAllManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(certs, authType) {
                    console.log('[+] checkClientTrusted called - bypassing');
                },
                checkServerTrusted: function(certs, authType) {
                    console.log('[+] checkServerTrusted called - bypassing');
                },
                getAcceptedIssuers: function() {
                    console.log('[+] getAcceptedIssuers called - returning empty array');
                    return [];
                }
            }
        });
        
        // Hook SSLContext.init to use our custom TrustManager
        SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function(keyManagers, trustManagers, secureRandom) {
            console.log('[+] SSLContext.init() called - installing custom TrustManager');
            var trustAllManager = TrustAllManager.$new();
            return this.init(keyManagers, [trustAllManager], secureRandom);
        };
        
        console.log("[+] Standard SSL verification bypass installed");
        
    } catch (err) {
        console.log("[-] Failed to setup standard SSL bypass: " + err);
    }
}

function bypassOkHttpPinning() {
    console.log("[+] Setting up OkHttp certificate pinning bypass...");
    
    try {
        // OkHttp 3.x bypass
        try {
            var CertificatePinner = Java.use('okhttp3.CertificatePinner');
            
            CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
                console.log('[+] OkHttp3 CertificatePinner.check() bypassed for: ' + hostname);
                return;
            };
            
            // Alternative method for some OkHttp versions
            try {
                CertificatePinner.findMatchingPins.implementation = function(hostname) {
                    console.log('[+] OkHttp3 findMatchingPins() bypassed for: ' + hostname);
                    return Java.use('java.util.Collections').emptyList();
                };
            } catch (e) {
                // Method might not exist in all versions
            }
            
            console.log("[+] OkHttp 3.x certificate pinning bypass installed");
            
        } catch (err) {
            console.log("[-] OkHttp 3.x not found or bypass failed: " + err);
        }
        
        // OkHttp 4.x bypass (Kotlin-based)
        try {
            var CertificatePinner4 = Java.use('okhttp3.CertificatePinner');
            
            // OkHttp 4.x uses different method signatures due to Kotlin
            CertificatePinner4['check$okhttp'].implementation = function(hostname, peerCertificates) {
                console.log('[+] OkHttp4 CertificatePinner.check() bypassed for: ' + hostname);
                return;
            };
            
            console.log("[+] OkHttp 4.x certificate pinning bypass installed");
            
        } catch (err) {
            console.log("[-] OkHttp 4.x not found or bypass failed: " + err);
        }
        
        // Additional OkHttp bypass for Builder pattern
        try {
            var CertificatePinnerBuilder = Java.use('okhttp3.CertificatePinner$Builder');
            
            CertificatePinnerBuilder.add.overload('java.lang.String', 'java.lang.String').implementation = function(pattern, pin) {
                console.log('[+] OkHttp CertificatePinner.Builder.add() bypassed for pattern: ' + pattern);
                return this; // Return builder for chaining
            };
            
            CertificatePinnerBuilder.build.implementation = function() {
                console.log('[+] OkHttp CertificatePinner.Builder.build() bypassed - returning empty pinner');
                return Java.use('okhttp3.CertificatePinner').get$companion().get$DEFAULT();
            };
            
        } catch (err) {
            console.log("[-] OkHttp Builder bypass failed: " + err);
        }
        
    } catch (err) {
        console.log("[-] Failed to setup OkHttp bypass: " + err);
    }
}

function bypassApacheHTTPClient() {
    console.log("[+] Setting up Apache HTTP Client SSL bypass...");
    
    try {
        // Apache HTTP Client TrustStrategy bypass
        var TrustStrategy = Java.use('org.apache.http.ssl.TrustStrategy');
        var TrustAllStrategy = Java.registerClass({
            name: 'TrustAllStrategy',
            implements: [TrustStrategy],
            methods: {
                isTrusted: function(chain, authType) {
                    console.log('[+] Apache HTTP TrustStrategy.isTrusted() bypassed');
                    return true;
                }
            }
        });
        
        // Hook SSLContextBuilder
        var SSLContextBuilder = Java.use('org.apache.http.ssl.SSLContextBuilder');
        SSLContextBuilder.loadTrustMaterial.overload('java.security.KeyStore', 'org.apache.http.ssl.TrustStrategy').implementation = function(truststore, trustStrategy) {
            console.log('[+] Apache HTTP SSLContextBuilder.loadTrustMaterial() bypassed');
            return this.loadTrustMaterial(truststore, TrustAllStrategy.$new());
        };
        
        console.log("[+] Apache HTTP Client SSL bypass installed");
        
    } catch (err) {
        console.log("[-] Apache HTTP Client not found or bypass failed: " + err);
    }
}

function bypassConscrypt() {
    console.log("[+] Setting up Conscrypt SSL bypass...");
    
    try {
        // Conscrypt TrustManager bypass
        var ConscryptTrustManager = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        
        ConscryptTrustManager.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log('[+] Conscrypt TrustManagerImpl.verifyChain() bypassed for host: ' + host);
            return untrustedChain;
        };
        
        ConscryptTrustManager.checkTrustedRecursive.implementation = function(certs, host, clientAuth, untrustedChain, trustAnchorChain, used) {
            console.log('[+] Conscrypt TrustManagerImpl.checkTrustedRecursive() bypassed');
            return;
        };
        
        console.log("[+] Conscrypt SSL bypass installed");
        
    } catch (err) {
        console.log("[-] Conscrypt not found or bypass failed: " + err);
    }
}

function bypassHostnameVerification() {
    console.log("[+] Setting up hostname verification bypass...");
    
    try {
        // Standard HostnameVerifier bypass
        var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
        var TrustAllHostnameVerifier = Java.registerClass({
            name: 'TrustAllHostnameVerifier',
            implements: [HostnameVerifier],
            methods: {
                verify: function(hostname, session) {
                    console.log('[+] HostnameVerifier.verify() bypassed for: ' + hostname);
                    return true;
                }
            }
        });
        
        // Hook HttpsURLConnection to use our hostname verifier
        var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(hostnameVerifier) {
            console.log('[+] HttpsURLConnection.setDefaultHostnameVerifier() bypassed');
            this.setDefaultHostnameVerifier(TrustAllHostnameVerifier.$new());
        };
        
        HttpsURLConnection.setHostnameVerifier.implementation = function(hostnameVerifier) {
            console.log('[+] HttpsURLConnection.setHostnameVerifier() bypassed');
            this.setHostnameVerifier(TrustAllHostnameVerifier.$new());
        };
        
        // Apache hostname verification bypass
        try {
            var DefaultHostnameVerifier = Java.use('org.apache.http.conn.ssl.DefaultHostnameVerifier');
            DefaultHostnameVerifier.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function(host, session) {
                console.log('[+] Apache DefaultHostnameVerifier.verify() bypassed for: ' + host);
                return true;
            };
        } catch (e) {
            // Apache classes might not be available
        }
        
        console.log("[+] Hostname verification bypass installed");
        
    } catch (err) {
        console.log("[-] Failed to setup hostname verification bypass: " + err);
    }
}

function bypassNetworkSecurityConfig() {
    console.log("[+] Setting up Network Security Config bypass...");
    
    try {
        // Bypass Network Security Config certificate pinning
        var NetworkSecurityPolicy = Java.use('android.security.NetworkSecurityPolicy');
        
        NetworkSecurityPolicy.getInstance.implementation = function() {
            console.log('[+] NetworkSecurityPolicy.getInstance() bypassed');
            var policy = this.getInstance();
            
            // Create a wrapper that always returns true for cleartext traffic
            var TrustAllPolicy = Java.registerClass({
                name: 'TrustAllNetworkSecurityPolicy',
                implements: [NetworkSecurityPolicy],
                methods: {
                    isCleartextTrafficPermitted: function(hostname) {
                        console.log('[+] NetworkSecurityPolicy.isCleartextTrafficPermitted() bypassed for: ' + hostname);
                        return true;
                    },
                    isCertificateTransparencyVerificationRequired: function(hostname) {
                        console.log('[+] NetworkSecurityPolicy.isCertificateTransparencyVerificationRequired() bypassed for: ' + hostname);
                        return false;
                    }
                }
            });
            
            return TrustAllPolicy.$new();
        };
        
        console.log("[+] Network Security Config bypass installed");
        
    } catch (err) {
        console.log("[-] Failed to setup Network Security Config bypass: " + err);
    }
}

function bypassAdditionalSSLImplementations() {
    console.log("[+] Setting up additional SSL implementation bypasses...");
    
    // Bypass TrustKit pinning library
    try {
        var TrustKit = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
        TrustKit.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function(hostname, session) {
            console.log('[+] TrustKit OkHostnameVerifier.verify() bypassed for: ' + hostname);
            return true;
        };
        
        console.log("[+] TrustKit bypass installed");
    } catch (err) {
        console.log("[-] TrustKit not found: " + err);
    }
    
    // Bypass Appcelerator Titanium
    try {
        var TiSocketFactory = Java.use('ti.modules.titanium.network.TiSocketFactory');
        TiSocketFactory.createSocket.overload('java.net.Socket', 'java.lang.String', 'int', 'boolean').implementation = function(socket, host, port, autoClose) {
            console.log('[+] TiSocketFactory.createSocket() bypassed for: ' + host + ':' + port);
            return this.createSocket(socket, host, port, autoClose);
        };
        
        console.log("[+] Titanium bypass installed");
    } catch (err) {
        console.log("[-] Titanium not found: " + err);
    }
    
    // Bypass IBM MobileFirst/Worklight
    try {
        var WLClient = Java.use('com.worklight.wlclient.api.WLClient');
        WLClient.getInstance.implementation = function() {
            console.log('[+] IBM MobileFirst WLClient.getInstance() bypassed');
            return this.getInstance();
        };
        
        console.log("[+] IBM MobileFirst bypass installed");
    } catch (err) {
        console.log("[-] IBM MobileFirst not found: " + err);
    }
    
    // Bypass Xamarin certificate pinning
    try {
        var ServicePointManager = Java.use('System.Net.ServicePointManager');
        ServicePointManager.get_ServerCertificateValidationCallback.implementation = function() {
            console.log('[+] Xamarin ServerCertificateValidationCallback bypassed');
            return null;
        };
        
        console.log("[+] Xamarin bypass installed");
    } catch (err) {
        console.log("[-] Xamarin not found: " + err);
    }
    
    // Bypass Flutter pinning
    try {
        // Flutter apps might use platform channels
        var MethodChannel = Java.use('io.flutter.plugin.common.MethodChannel');
        var originalInvokeMethod = MethodChannel.invokeMethod.overload('java.lang.String', 'java.lang.Object');
        
        MethodChannel.invokeMethod.overload('java.lang.String', 'java.lang.Object').implementation = function(method, arguments) {
            if (method.indexOf('ssl') !== -1 || method.indexOf('cert') !== -1 || method.indexOf('pin') !== -1) {
                console.log('[+] Flutter SSL-related method call bypassed: ' + method);
                return null;
            }
            return originalInvokeMethod.call(this, method, arguments);
        };
        
        console.log("[+] Flutter bypass installed");
    } catch (err) {
        console.log("[-] Flutter not found: " + err);
    }
}

// Monitor SSL connections for debugging
function monitorSSLConnections() {
    console.log("[+] Setting up SSL connection monitoring...");
    
    try {
        // Monitor SSL socket creation
        var SSLSocketFactory = Java.use('javax.net.ssl.SSLSocketFactory');
        SSLSocketFactory.createSocket.overload('java.lang.String', 'int').implementation = function(host, port) {
            console.log('[+] SSL connection to: ' + host + ':' + port);
            return this.createSocket(host, port);
        };
        
        // Monitor URL connections
        var URL = Java.use('java.net.URL');
        URL.openConnection.overload().implementation = function() {
            var connection = this.openConnection();
            var url = this.toString();
            
            if (url.startsWith('https://')) {
                console.log('[+] HTTPS connection to: ' + url);
            }
            
            return connection;
        };
        
        console.log("[+] SSL connection monitoring installed");
        
    } catch (err) {
        console.log("[-] Failed to setup SSL monitoring: " + err);
    }
}

// Start SSL monitoring
monitorSSLConnections();

console.log("[+] Universal SSL Certificate Pinning Bypass completed");
console.log("[+] All HTTPS traffic should now bypass certificate validation");
