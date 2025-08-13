// OWASP M1: Permission Monitoring Script
// Monitors runtime permission requests and checks

console.log("[+] OWASP M1 Permission Monitor loaded");

Java.perform(function() {
    console.log("[*] Hooking permission-related methods...");
    
    // Hook ActivityCompat.checkSelfPermission
    try {
        var ActivityCompat = Java.use("androidx.core.app.ActivityCompat");
        ActivityCompat.checkSelfPermission.implementation = function(context, permission) {
            console.log("[+] Permission check: " + permission);
            var result = this.checkSelfPermission(context, permission);
            console.log("    Result: " + (result === 0 ? "GRANTED" : "DENIED"));
            return result;
        };
        console.log("[+] Hooked ActivityCompat.checkSelfPermission");
    } catch (e) {
        console.log("[-] Failed to hook ActivityCompat: " + e);
    }
    
    // Hook Activity.requestPermissions
    try {
        var Activity = Java.use("android.app.Activity");
        Activity.requestPermissions.implementation = function(permissions, requestCode) {
            console.log("[+] Requesting permissions (code " + requestCode + "):");
            for (var i = 0; i < permissions.length; i++) {
                console.log("    " + permissions[i]);
            }
            return this.requestPermissions(permissions, requestCode);
        };
        console.log("[+] Hooked Activity.requestPermissions");
    } catch (e) {
        console.log("[-] Failed to hook Activity.requestPermissions: " + e);
    }
    
    // Hook ContextCompat.checkSelfPermission
    try {
        var ContextCompat = Java.use("androidx.core.content.ContextCompat");
        ContextCompat.checkSelfPermission.implementation = function(context, permission) {
            console.log("[+] ContextCompat permission check: " + permission);
            var result = this.checkSelfPermission(context, permission);
            console.log("    Result: " + (result === 0 ? "GRANTED" : "DENIED"));
            return result;
        };
        console.log("[+] Hooked ContextCompat.checkSelfPermission");
    } catch (e) {
        console.log("[-] Failed to hook ContextCompat: " + e);
    }
    
    // Hook dangerous permission usage
    var dangerousPermissions = [
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.CALL_PHONE",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE"
    ];
    
    // Monitor PackageManager.checkPermission
    try {
        var PackageManager = Java.use("android.content.pm.PackageManager");
        PackageManager.checkPermission.implementation = function(permission, packageName) {
            var result = this.checkPermission(permission, packageName);
            if (dangerousPermissions.indexOf(permission) !== -1) {
                console.log("[!] Dangerous permission check: " + permission + " for " + packageName);
                console.log("    Result: " + (result === 0 ? "GRANTED" : "DENIED"));
            }
            return result;
        };
        console.log("[+] Hooked PackageManager.checkPermission");
    } catch (e) {
        console.log("[-] Failed to hook PackageManager: " + e);
    }
    
    // Monitor file access permissions
    try {
        var FileOutputStream = Java.use("java.io.FileOutputStream");
        FileOutputStream.$init.overload('java.io.File', 'boolean').implementation = function(file, append) {
            console.log("[+] File write access: " + file.getAbsolutePath());
            return this.$init(file, append);
        };
        console.log("[+] Hooked FileOutputStream");
    } catch (e) {
        console.log("[-] Failed to hook FileOutputStream: " + e);
    }
    
    console.log("[+] Permission monitoring hooks installed");
});
