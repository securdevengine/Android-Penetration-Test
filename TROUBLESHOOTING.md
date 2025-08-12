Android Reverse Engineering Toolkit - Troubleshooting Guide

This guide provides solutions for common real-world environment issues encountered during Android reverse engineering.

Device Detection Issues

ADB Device Not Detected

Problem: Device shows as offline or not detected
Solutions:

1. Basic ADB Reset
adb kill-server
adb start-server
adb devices

2. USB Debugging Issues
Enable USB Debugging on device:
- Settings > Developer Options > USB Debugging
- Settings > Developer Options > Install via USB
- Settings > Developer Options > USB Debugging (Security Settings)

3. USB Driver Issues (Windows)
Download and install device-specific USB drivers
Use Universal ADB Driver if official drivers fail
Enable "Install from Unknown Sources" for driver installation

4. USB Connection Mode
Change USB connection mode to "File Transfer" or "MTP"
Try different USB cables (some are power-only)
Test different USB ports (avoid USB hubs)

5. RSA Key Authorization
Accept RSA fingerprint on device when prompted
Delete .android/adbkey* files and reconnect if stuck
adb connect localhost:5555 (for emulator)

Device Shows Unauthorized

Problem: Device appears in adb devices as "unauthorized"
Solutions:

1. Clear ADB Keys
rm ~/.android/adbkey*
adb kill-server
adb start-server

2. Revoke USB Debugging Authorization
Settings > Developer Options > Revoke USB Debugging Authorizations
Reconnect device and accept new RSA key

3. Check Device Screen
Ensure device screen is unlocked when connecting
Some devices require screen to be on for ADB authorization

ADB Port and Network Issues

ADB Port Already in Use

Problem: "cannot bind to socket" error
Solutions:

1. Find and Kill Process Using Port 5037
Windows:
netstat -ano | findstr :5037
taskkill /PID <process_id> /F

Linux/Mac:
lsof -ti:5037 | xargs kill -9
sudo fuser -k 5037/tcp

2. Use Alternative ADB Port
adb -P 5038 start-server
export ANDROID_ADB_SERVER_PORT=5038

3. Network ADB Setup
adb tcpip 5555
adb connect <device_ip>:5555
adb devices

Emulator Connection Issues

Problem: Emulator not detected by ADB
Solutions:

1. Manual Emulator Connection
adb connect 127.0.0.1:5554
adb connect localhost:5555

2. Emulator Port Conflicts
emulator -avd <name> -port 5556
adb connect localhost:5557

3. Cold Boot Emulator
emulator -avd <name> -wipe-data -no-snapshot

Environment Variables and Path Issues

ANDROID_HOME Not Set

Problem: Tools can't find Android SDK
Solutions:

1. Set Environment Variables
Linux/Mac:
export ANDROID_HOME=$HOME/Android/Sdk
export PATH=$PATH:$ANDROID_HOME/platform-tools:$ANDROID_HOME/tools

Windows:
set ANDROID_HOME=C:\Users\%USERNAME%\AppData\Local\Android\Sdk
set PATH=%PATH%;%ANDROID_HOME%\platform-tools

2. Persistent Environment Setup
Add to ~/.bashrc or ~/.zshrc:
export ANDROID_HOME=$HOME/Android/Sdk
export PATH=$PATH:$ANDROID_HOME/platform-tools:$ANDROID_HOME/tools

3. SDK Detection Script
Create auto_detect_sdk.sh:
#!/bin/bash
for path in "$HOME/Android/Sdk" "/opt/android-sdk" "/usr/local/android-sdk"; do
    if [ -d "$path" ]; then
        export ANDROID_HOME="$path"
        export PATH="$PATH:$ANDROID_HOME/platform-tools:$ANDROID_HOME/tools"
        echo "Android SDK found at: $path"
        break
    fi
done

Tool Path Issues

Problem: jadx, apktool, or other tools not found
Solutions:

1. Tool Detection Function
check_tool() {
    if ! command -v $1 &> /dev/null; then
        echo "[$1] not found. Installing..."
        case $1 in
            "jadx")
                wget -O /tmp/jadx.zip https://github.com/skylot/jadx/releases/latest/download/jadx-1.4.7.zip
                unzip /tmp/jadx.zip -d tools/jadx
                sudo ln -sf $(pwd)/tools/jadx/bin/jadx /usr/local/bin/jadx
                ;;
            "apktool")
                wget -O tools/apktool.jar https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.7.0.jar
                echo '#!/bin/bash\njava -jar '$(pwd)'/tools/apktool.jar "$@"' > tools/apktool
                chmod +x tools/apktool
                sudo ln -sf $(pwd)/tools/apktool /usr/local/bin/apktool
                ;;
        esac
    fi
}

2. Relative Path Solution
Create wrapper scripts that use absolute paths:
#!/bin/bash
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
java -jar "$SCRIPT_DIR/tools/apktool.jar" "$@"

Frida-Specific Issues

Frida Server Not Starting

Problem: Frida server fails to start on device
Solutions:

1. Architecture Mismatch
Check device architecture:
adb shell getprop ro.product.cpu.abi

Download correct Frida server:
wget https://github.com/frida/frida/releases/download/16.1.4/frida-server-16.1.4-android-arm64.xz

2. Permission Issues
adb push frida-server /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server
adb shell su -c "/data/local/tmp/frida-server &"

3. SELinux Issues
adb shell su -c "setenforce 0"
adb shell su -c "/data/local/tmp/frida-server &"

4. Port Conflicts
adb shell su -c "/data/local/tmp/frida-server -l 0.0.0.0:27043 &"
frida -H 127.0.0.1:27043 -f com.example.app

Frida Connection Failed

Problem: Can't connect to Frida server
Solutions:

1. Check Server Status
adb shell su -c "ps | grep frida"

2. Port Forwarding
adb forward tcp:27042 tcp:27042

3. Network Connection
adb shell su -c "netstat -tuln | grep 27042"

4. Restart Frida Server
adb shell su -c "killall frida-server"
adb shell su -c "/data/local/tmp/frida-server &"

Process Attachment Issues

Problem: Frida can't attach to target process
Solutions:

1. Spawn vs Attach Mode
Use spawn mode for early hooking:
frida -U -f com.example.app -l script.js --no-pause

Use attach mode for running apps:
frida -U -n "App Name" -l script.js

2. Root Detection Bypass
Load anti-root scripts before target app:
frida -U -f com.example.app -l anti_root.js -l main_script.js --no-pause

3. Process Name Issues
List all processes:
frida-ps -U

Use package name instead of process name:
frida -U com.example.app

Network and SSL Issues

Burp Suite Certificate Issues

Problem: SSL certificate not trusted by app
Solutions:

1. System Certificate Installation
Convert Burp cert to system format:
openssl x509 -inform DER -in cacert.der -out cacert.pem
openssl x509 -inform PEM -subject_hash_old -in cacert.pem | head -1
mv cacert.pem <hash>.0

Install to system:
adb push <hash>.0 /sdcard/
adb shell su -c "mount -o rw,remount /system"
adb shell su -c "cp /sdcard/<hash>.0 /system/etc/security/cacerts/"
adb shell su -c "chmod 644 /system/etc/security/cacerts/<hash>.0"
adb shell su -c "reboot"

2. User Certificate Method
Export Burp certificate as DER
Install via Settings > Security > Install from storage

3. Magisk Module Method
Use "Move Certificates" Magisk module
Automatically moves user certs to system store

Proxy Configuration Issues

Problem: Device not routing traffic through proxy
Solutions:

1. Manual Proxy Setup
adb shell settings put global http_proxy <proxy_ip>:8080

2. WiFi Proxy Configuration
Settings > WiFi > Modify Network > Advanced > Proxy

3. VPN-based Proxy
Use tools like ProxyDroid or Drony
Route all traffic through Burp Suite

4. Iptables Rules (Root Required)
adb shell su -c "iptables -t nat -A OUTPUT -p tcp --dport 80 -j DNAT --to-destination <proxy_ip>:8080"
adb shell su -c "iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination <proxy_ip>:8080"

SSL Pinning Bypass Issues

Problem: SSL pinning bypass not working
Solutions:

1. Multiple Bypass Techniques
Load multiple bypass scripts:
frida -U -f com.example.app -l ssl_kill_switch.js -l universal_ssl_bypass.js --no-pause

2. Custom Pinning Implementation
Identify app-specific pinning:
frida-trace -U -f com.example.app -I "*ssl*" -I "*tls*" -I "*certificate*"

3. Native Library Pinning
Hook native SSL functions:
Interceptor.attach(Module.findExportByName("libssl.so", "SSL_CTX_set_verify"), {
    onEnter: function(args) {
        console.log("[+] SSL_CTX_set_verify bypass");
        args[1] = ptr(0);
    }
});

Permission and Root Issues

Root Access Problems

Problem: Apps detect root and refuse to run
Solutions:

1. Magisk Hide
Enable Magisk Hide for target app
Use "Universal SafetyNet Fix" module

2. Root Hiding Scripts
Load root bypass before app starts:
frida -U -f com.example.app -l root_bypass.js --no-pause

3. Custom Boot Image
Use Magisk-patched boot image
Hide Magisk app and rename it

Device Storage Issues

Problem: Insufficient storage for analysis
Solutions:

1. External Storage Analysis
adb shell mkdir /sdcard/analysis
adb push analysis_data /sdcard/analysis/

2. Network Storage
Mount network storage:
adb shell su -c "mount -t cifs //<server>/<share> /mnt/analysis"

3. Streaming Analysis
Stream data directly without local storage:
frida -U -f com.example.app -l streaming_script.js | nc <server> <port>

Performance Issues

Slow Analysis Performance

Problem: Analysis takes too long
Solutions:

1. Resource Optimization
Limit concurrent processes:
ulimit -n 1024
nice -n 10 python apk_analyzer.py

2. Parallel Processing
Use multiprocessing for bulk analysis:
find . -name "*.apk" | xargs -P 4 -I {} python apk_analyzer.py {}

3. Memory Management
Monitor memory usage:
watch -n 1 'free -h'
Set memory limits for analysis tools

Advanced Troubleshooting

Debugging Frida Scripts

Problem: Frida scripts not working as expected
Solutions:

1. Enable Verbose Logging
console.log("[DEBUG] Script loaded");
Process.enumerateModules().forEach(function(module) {
    console.log("[+] Module: " + module.name);
});

2. Error Handling
try {
    var targetClass = Java.use("com.example.TargetClass");
    // Hook implementation
} catch (e) {
    console.log("[-] Error: " + e.message);
    console.log("[-] Available classes:");
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.indexOf("example") !== -1) {
                console.log("    " + className);
            }
        },
        onComplete: function() {}
    });
}

3. Runtime Class Discovery
Java.perform(function() {
    Java.choose("android.app.Activity", {
        onMatch: function(instance) {
            console.log("[+] Found activity: " + instance);
        },
        onComplete: function() {}
    });
});

Environment Consistency

Problem: Inconsistent behavior across environments
Solutions:

1. Docker Environment
Create consistent environment:
FROM ubuntu:20.04
RUN apt-get update && apt-get install -y android-tools-adb
COPY . /toolkit
WORKDIR /toolkit

2. Virtual Machine
Use pre-configured VM with all tools
Export/import VM snapshots for consistency

3. Version Pinning
Pin tool versions in requirements:
frida==16.1.4
frida-tools==12.2.1

Quick Diagnostic Commands

Device Status Check
adb devices -l
adb shell getprop ro.build.version.release
adb shell getprop ro.product.cpu.abi

Frida Status Check
frida --version
frida-ps -U
frida-ls-devices

Network Status Check
adb shell netstat -tuln
adb shell settings get global http_proxy
ping <proxy_ip>

Tool Verification
jadx --version
apktool --version
java -version
python3 --version

Emergency Recovery

Complete Environment Reset
adb kill-server
pkill -f frida
rm -rf ~/.android/adb*
./setup.sh

Factory Reset Preparation
Backup important data before factory reset
Use Titanium Backup for app data
Create NANDroid backup with TWRP

This troubleshooting guide covers the most common real-world issues. For specific problems not covered here, enable verbose logging and check the specific error messages for targeted solutions.
