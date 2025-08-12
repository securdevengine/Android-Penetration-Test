Environment Setup Guide

This guide walks you through setting up a complete Android reverse engineering environment for penetration testing and security analysis.

Prerequisites

System Requirements
- OS: Linux (Ubuntu 20.04+ recommended), macOS, or Windows with WSL2
- RAM: Minimum 8GB (16GB+ recommended)
- Storage: At least 50GB free space
- Java: JDK 8 or higher
- Python: 3.8+ with pip

Hardware Requirements
- Android Device: Rooted physical device OR
- Android Emulator: AVD with Google APIs (API level 28+)

Step 1: Android Development Environment

Install Android SDK
Download Android SDK Command Line Tools
wget https://dl.google.com/android/repository/commandlinetools-linux-8512546_latest.zip
unzip commandlinetools-linux-8512546_latest.zip -d ~/android-sdk
export ANDROID_HOME=~/android-sdk
export PATH=$PATH:$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools

Install essential packages
sdkmanager "platform-tools" "platforms;android-30" "build-tools;30.0.3"

### Setup ADB
```bash
# Verify ADB installation
adb version

# Enable USB debugging on your device
# Settings → Developer Options → USB Debugging
adb devices
```

## 🔨 Step 2: Root Android Device

### Option 1: Physical Device (Recommended)

#### Method 1: Magisk (Universal)
```bash
# Download Magisk Manager APK
wget https://github.com/topjohnwu/Magisk/releases/latest/download/Magisk-v25.2.apk

# Install on device
adb install Magisk-v25.2.apk

# Extract boot.img from device
adb shell dd if=/dev/block/bootdevice/by-name/boot of=/sdcard/boot.img
adb pull /sdcard/boot.img

# Patch with Magisk Manager (follow app instructions)
# Flash patched boot image
adb reboot bootloader
fastboot flash boot magisk_patched.img
fastboot reboot
```

#### Method 2: Device-Specific Exploits
```bash
# Samsung devices (Odin)
# 1. Download appropriate firmware
# 2. Extract AP file
# 3. Patch with Magisk
# 4. Flash via Odin

# Google Pixel (Fastboot)
fastboot flashing unlock
fastboot flash boot magisk_patched.img
```

### Option 2: Android Emulator
```bash
# Create AVD with Google APIs
avd create -n "test_avd" -k "system-images;android-30;google_apis;x86_64"

# Start emulator with writable system
emulator -avd test_avd -writable-system -no-snapshot

# Root emulator
adb root
adb remount
```

### Verify Root Access
```bash
adb shell
su
id  # Should show uid=0(root)
```

## 🛠️ Step 3: Install Core Tools

### Static Analysis Tools

#### JADX (APK Decompiler)
```bash
cd tools/jadx
wget https://github.com/skylot/jadx/releases/latest/download/jadx-1.4.7.zip
unzip jadx-1.4.7.zip
chmod +x bin/jadx*
export PATH=$PATH:$(pwd)/bin
```

#### APKTool (Resource Extractor)
```bash
cd tools/apktool
wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool
wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.7.0.jar
chmod +x apktool
export PATH=$PATH:$(pwd)
```

#### Ghidra (Native Library Analysis)
```bash
cd tools/ghidra
wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.4_build/ghidra_10.4_PUBLIC_20230928.zip
unzip ghidra_10.4_PUBLIC_20230928.zip
export GHIDRA_INSTALL_DIR=$(pwd)/ghidra_10.4_PUBLIC
```

#### MobSF (Automated Scanner)
```bash
# Docker installation (recommended)
docker pull opensecurity/mobsf:latest
docker run -it --rm -p 8000:8000 opensecurity/mobsf:latest

# Or manual installation
git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git
cd Mobile-Security-Framework-MobSF
pip install -r requirements.txt
python manage.py runserver 0.0.0.0:8000
```

### Dynamic Analysis Tools

#### Frida (Runtime Instrumentation)
```bash
# Install Frida on host
pip install frida-tools

# Download Frida server for Android
wget https://github.com/frida/frida/releases/download/16.1.4/frida-server-16.1.4-android-arm64.xz
unxz frida-server-16.1.4-android-arm64.xz

# Push to device
adb push frida-server-16.1.4-android-arm64 /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server

# Start Frida server
adb shell "/data/local/tmp/frida-server &"

# Verify connection
frida-ps -U
```

#### Objection (Frida Frontend)
```bash
pip install objection
objection version
```

#### Burp Suite (Traffic Interception)
```bash
# Download Burp Suite Community
wget https://portswigger.net/burp/releases/download?product=community&type=Linux
java -jar burpsuite_community_linux_v2023_10_2_4.jar

# Configure Android device proxy
adb shell settings put global http_proxy 192.168.1.100:8080
```

#### Drozer (Component Testing)
```bash
pip install drozer
wget https://github.com/FSecureLABS/drozer/releases/download/2.4.4/drozer-agent-2.4.4.apk
adb install drozer-agent-2.4.4.apk
```

## 🔐 Step 4: SSL Certificate Setup

### Install Burp CA Certificate
```bash
# Export Burp CA certificate
# Burp → Proxy → Options → Import/Export CA Certificate

# Convert to Android format
openssl x509 -inform DER -in cacert.der -out cacert.pem
openssl x509 -inform PEM -subject_hash_old -in cacert.pem | head -1
mv cacert.pem <hash>.0

# Push to device
adb push <hash>.0 /system/etc/security/cacerts/
adb shell chmod 644 /system/etc/security/cacerts/<hash>.0
adb reboot
```

### Bypass Network Security Config
```bash
# Create custom network security config
cat > network_security_config.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <debug-overrides>
        <trust-anchors>
            <certificates src="user"/>
            <certificates src="system"/>
        </trust-anchors>
    </debug-overrides>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="user"/>
            <certificates src="system"/>
        </trust-anchors>
    </base-config>
</network-security-config>
EOF
```

## 🚀 Step 5: Framework Installation

### Install Python Dependencies
```bash
pip install -r requirements.txt
```

### Verify Installation
```bash
# Run verification script
python scripts/utils/verify_setup.py
```

## 📱 Step 6: Device Configuration

### Enable Developer Options
1. Settings → About Phone
2. Tap "Build Number" 7 times
3. Settings → Developer Options
4. Enable USB Debugging
5. Enable Stay Awake
6. Disable Verify Apps

### Configure Network Settings
```bash
# Set proxy for HTTP traffic
adb shell settings put global http_proxy 192.168.1.100:8080

# Disable mobile data (optional)
adb shell svc data disable

# Enable WiFi
adb shell svc wifi enable
```

### Install Testing Apps
```bash
# Install vulnerable test applications
adb install samples/vulnerable_app.apk
adb install samples/insecurebankv2.apk
```

## 🔍 Step 7: Verification

### Test Static Analysis
```bash
# Test JADX decompilation
jadx samples/vulnerable_app.apk -d output/jadx_output

# Test APKTool extraction
apktool d samples/vulnerable_app.apk -o output/apktool_output
```

### Test Dynamic Analysis
```bash
# Test Frida connection
frida-ps -U

# Test Objection
objection -g com.example.vulnerable explore

# Test Burp Suite proxy
curl -x http://127.0.0.1:8080 http://httpbin.org/ip
```

### Test Anti-Debug Bypass
```bash
# Load bypass script
frida -U -l frida_scripts/anti_debug/ptrace_bypass.js -f com.example.vulnerable --no-pause
```

## 🚨 Troubleshooting

### Common Issues

#### ADB Device Not Found
```bash
# Kill and restart ADB server
adb kill-server
adb start-server
adb devices
```

#### Frida Connection Failed
```bash
# Check Frida server process
adb shell ps | grep frida-server

# Restart Frida server
adb shell "killall frida-server"
adb shell "/data/local/tmp/frida-server &"
```

#### SSL Pinning Bypass Failed
```bash
# Use universal SSL bypass
objection -g com.example.app explore
android sslpinning disable
```

#### Root Detection
```bash
# Hide root with Magisk Hide
# Or use runtime bypass
objection -g com.example.app explore
android root disable
```

## 📈 Performance Optimization

### Emulator Settings
```bash
# Increase emulator RAM
emulator -avd test_avd -memory 4096

# Enable hardware acceleration
emulator -avd test_avd -gpu host
```

### Frida Optimization
```bash
# Use spawning mode for better hook timing
frida -U -f com.example.app -l script.js --no-pause

# Batch operations for better performance
frida -U -l multiple_hooks.js com.example.app
```

## 🔗 Next Steps

1. ✅ Environment Setup Complete
2. 📖 Continue to [Static Analysis Guide](02-static-analysis.md)
3. 🔬 Learn [Dynamic Analysis Techniques](03-dynamic-analysis.md)
4. 🔐 Master [Authentication Analysis](04-authentication-analysis.md)
5. 🛡️ Study [Anti-Debugging Bypass](05-anti-debugging-bypass.md)

## 📚 Additional Resources

- [Android Developer Documentation](https://developer.android.com/)
- [Frida Documentation](https://frida.re/docs/)
- [OWASP Mobile Security](https://owasp.org/www-project-mobile-security-testing-guide/)
- [Android Security Internals](https://nostarch.com/androidsecurity)
