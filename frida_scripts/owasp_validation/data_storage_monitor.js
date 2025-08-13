// OWASP M2: Insecure Data Storage Monitor
// Monitors file operations, SharedPreferences, and database access

console.log("[+] OWASP M2 Data Storage Monitor loaded");

Java.perform(function() {
    console.log("[*] Hooking data storage methods...");
    
    // Monitor SharedPreferences
    try {
        var SharedPreferences = Java.use("android.content.SharedPreferences");
        var Editor = Java.use("android.content.SharedPreferences$Editor");
        
        // Hook SharedPreferences.getString
        SharedPreferences.getString.overload('java.lang.String', 'java.lang.String').implementation = function(key, defValue) {
            var result = this.getString(key, defValue);
            console.log("[+] SharedPreferences.getString: " + key + " = " + result);
            if (key.toLowerCase().includes('password') || key.toLowerCase().includes('secret') || 
                key.toLowerCase().includes('token') || key.toLowerCase().includes('key')) {
                console.log("[!] Sensitive key accessed: " + key);
            }
            return result;
        };
        
        // Hook Editor.putString
        Editor.putString.implementation = function(key, value) {
            console.log("[+] SharedPreferences.putString: " + key + " = " + value);
            if (key.toLowerCase().includes('password') || key.toLowerCase().includes('secret') || 
                key.toLowerCase().includes('token') || key.toLowerCase().includes('key')) {
                console.log("[!] Sensitive data stored: " + key + " = " + value);
            }
            return this.putString(key, value);
        };
        
        console.log("[+] Hooked SharedPreferences");
    } catch (e) {
        console.log("[-] Failed to hook SharedPreferences: " + e);
    }
    
    // Monitor SQLite Database operations
    try {
        var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
        
        // Hook execSQL
        SQLiteDatabase.execSQL.overload('java.lang.String').implementation = function(sql) {
            console.log("[+] SQLiteDatabase.execSQL: " + sql);
            if (sql.toLowerCase().includes('create table') || sql.toLowerCase().includes('insert into') ||
                sql.toLowerCase().includes('update') || sql.toLowerCase().includes('delete from')) {
                console.log("[*] Database modification: " + sql);
            }
            return this.execSQL(sql);
        };
        
        // Hook rawQuery
        SQLiteDatabase.rawQuery.overload('java.lang.String', '[Ljava.lang.String;').implementation = function(sql, args) {
            console.log("[+] SQLiteDatabase.rawQuery: " + sql);
            if (args) {
                console.log("    Args: " + args.join(", "));
            }
            return this.rawQuery(sql, args);
        };
        
        console.log("[+] Hooked SQLiteDatabase");
    } catch (e) {
        console.log("[-] Failed to hook SQLiteDatabase: " + e);
    }
    
    // Monitor file operations
    try {
        var FileOutputStream = Java.use("java.io.FileOutputStream");
        var FileInputStream = Java.use("java.io.FileInputStream");
        
        FileOutputStream.$init.overload('java.lang.String').implementation = function(name) {
            console.log("[+] FileOutputStream created: " + name);
            if (name.includes('/sdcard/') || name.includes('/external/')) {
                console.log("[!] Writing to external storage: " + name);
            }
            return this.$init(name);
        };
        
        FileInputStream.$init.overload('java.lang.String').implementation = function(name) {
            console.log("[+] FileInputStream created: " + name);
            return this.$init(name);
        };
        
        console.log("[+] Hooked File I/O operations");
    } catch (e) {
        console.log("[-] Failed to hook File operations: " + e);
    }
    
    // Monitor logging for sensitive data
    try {
        var Log = Java.use("android.util.Log");
        
        var logMethods = ['d', 'i', 'w', 'e', 'v'];
        logMethods.forEach(function(method) {
            try {
                Log[method].overload('java.lang.String', 'java.lang.String').implementation = function(tag, msg) {
                    if (msg && (msg.toLowerCase().includes('password') || msg.toLowerCase().includes('secret') ||
                               msg.toLowerCase().includes('token') || msg.toLowerCase().includes('key') ||
                               msg.toLowerCase().includes('auth'))) {
                        console.log("[!] Sensitive data in log (" + method + "): " + tag + " - " + msg);
                    }
                    return this[method](tag, msg);
                };
            } catch (e) {
                // Method might not exist
            }
        });
        
        console.log("[+] Hooked Log methods");
    } catch (e) {
        console.log("[-] Failed to hook Log: " + e);
    }
    
    // Monitor clipboard operations
    try {
        var ClipboardManager = Java.use("android.content.ClipboardManager");
        
        ClipboardManager.setPrimaryClip.implementation = function(clip) {
            try {
                var item = clip.getItemAt(0);
                var text = item.getText();
                console.log("[+] Clipboard set: " + text);
                if (text && (text.toString().toLowerCase().includes('password') || 
                           text.toString().toLowerCase().includes('secret'))) {
                    console.log("[!] Sensitive data copied to clipboard");
                }
            } catch (e) {
                console.log("[+] Clipboard set (could not read content)");
            }
            return this.setPrimaryClip(clip);
        };
        
        console.log("[+] Hooked ClipboardManager");
    } catch (e) {
        console.log("[-] Failed to hook ClipboardManager: " + e);
    }
    
    // Monitor external storage access
    try {
        var Environment = Java.use("android.os.Environment");
        
        Environment.getExternalStorageDirectory.implementation = function() {
            var result = this.getExternalStorageDirectory();
            console.log("[+] External storage accessed: " + result.getAbsolutePath());
            return result;
        };
        
        console.log("[+] Hooked Environment.getExternalStorageDirectory");
    } catch (e) {
        console.log("[-] Failed to hook Environment: " + e);
    }
    
    console.log("[+] Data storage monitoring hooks installed");
});
