Setup Guide

This guide will help you set up the Android Reverse Engineering Toolkit on your system.

Prerequisites

System Requirements
- Operating System: Linux (Ubuntu 20.04+), macOS (10.15+), or Windows 10/11 with WSL2
- RAM: Minimum 8GB (16GB+ recommended)
- Storage: At least 10GB free space
- Python: 3.8 or higher
- Java: JDK 8 or higher

Hardware Requirements
- Android Device: Rooted physical device OR
- Android Emulator: AVD with Google APIs (API level 28+)

Quick Setup (Recommended)

1. Clone the Repository
git clone https://github.com/your-repo/android-reverse-engineering-toolkit.git
cd android-reverse-engineering-toolkit

2. Run Setup Script
chmod +x setup.sh
./setup.sh

The setup script will automatically:
- Install system dependencies
- Download and configure reverse engineering tools
- Set up Python virtual environment
- Install Python packages
- Create necessary directories
- Generate configuration files

3. Activate Environment
source setup_env.sh

4. Verify Installation
python verify_setup.py

Manual Setup

If the automatic setup fails, follow these manual steps:

1. Install System Dependencies

Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-venv openjdk-11-jdk android-tools-adb android-tools-fastboot git curl wget unzip build-essential libssl-dev libffi-dev aapt zipalign

macOS
Install Homebrew if not installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

Install dependencies
brew install python3 openjdk@11 android-platform-tools git curl wget unzip

Windows (WSL2)
Follow Ubuntu instructions within WSL2
Additional Windows-specific tools may be needed

### 2. Setup Android SDK

Download Android SDK
Create SDK directory
mkdir -p ~/android-sdk
cd ~/android-sdk

Download command line tools
wget https://dl.google.com/android/repository/commandlinetools-linux-8512546_latest.zip
unzip commandlinetools-linux-8512546_latest.zip

Set up environment
export ANDROID_HOME=~/android-sdk
export PATH=$PATH:$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools

Install essential packages
sdkmanager "platform-tools" "platforms;android-30" "build-tools;30.0.3"

3. Setup Python Environment
Create virtual environment
python3 -m venv venv
source venv/bin/activate

Upgrade pip
pip install --upgrade pip

Install dependencies
pip install -r requirements.txt

### 4. Download Tools

JADX (APK Decompiler)
mkdir -p tools/jadx
cd tools/jadx
wget https://github.com/skylot/jadx/releases/latest/download/jadx-1.4.7.zip
unzip jadx-1.4.7.zip
chmod +x bin/jadx*
cd ../..

APKTool (Resource Extractor)
cd tools
wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool
wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.7.0.jar
chmod +x apktool
cd ..

Frida
pip install frida-tools

Download Frida server for Android
wget https://github.com/frida/frida/releases/download/16.1.4/frida-server-16.1.4-android-arm64.xz
unxz frida-server-16.1.4-android-arm64.xz

## Device Setup

### 1. Enable USB Debugging
1. Go to Settings → About Phone
2. Tap "Build Number" 7 times to enable Developer Options
3. Go to Settings → Developer Options
4. Enable "USB Debugging"
5. Enable "Stay Awake"

### 2. Root Device (Physical Device)

For comprehensive rooting techniques including KernelSU, SuperSU, and device-specific methods, see: docs/06-rooting-techniques.md

Quick Magisk Setup (Recommended):
Download Magisk Manager
wget https://github.com/topjohnwu/Magisk/releases/latest/download/Magisk-v26.1.apk
adb install Magisk-v26.1.apk

Extract boot image from device
adb shell dd if=/dev/block/bootdevice/by-name/boot of=/sdcard/boot.img
adb pull /sdcard/boot.img

Patch with Magisk Manager (follow app instructions)
Flash patched boot image
adb reboot bootloader
fastboot flash boot magisk_patched.img
fastboot reboot

Alternative: KernelSU (Kernel-level Root)
For devices with kernel source availability:
wget https://github.com/tiann/KernelSU/releases/latest/download/KernelSU_<version>.apk
adb install KernelSU_<version>.apk
Flash KernelSU-enabled kernel or use module method

3. Setup Android Emulator (Alternative)
Create AVD
avd create -n "security_test" -k "system-images;android-30;google_apis;x86_64"

Start emulator with root
emulator -avd security_test -writable-system -no-snapshot &

Root emulator
adb root
adb remount

4. Install Frida Server
Push Frida server to device
adb push frida-server-16.1.4-android-arm64 /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server

Start Frida server
adb shell "/data/local/tmp/frida-server &"

Verify connection
frida-ps -U

## Configuration

1. Burp Suite Setup (Optional)
Install Burp Suite Community/Professional
Configure proxy: 127.0.0.1:8080

Install CA certificate on device
Burp → Proxy → Options → Import/Export CA Certificate
Push certificate to device and install

2. Network Configuration
Set device proxy (if using Burp Suite)
adb shell settings put global http_proxy 192.168.1.100:8080

Disable mobile data (optional)
adb shell svc data disable

## Verification

1. Test Tools
Test JADX
jadx --version

Test APKTool
apktool --version

Test ADB
adb devices

Test Frida
frida-ps -U

2. Run Test Analysis
Download test APK
wget https://github.com/OWASP/MASTG-Hacking-Playground/releases/download/1.0/MASTG-Hacking-Playground.apk

Test static analysis
python scripts/static_analysis/apk_analyzer.py MASTG-Hacking-Playground.apk

Install test app
adb install MASTG-Hacking-Playground.apk

Test dynamic analysis
python scripts/dynamic_analysis/frida_automation.py sg.vp.owasp_mobile.omtg_android

## Troubleshooting

### Common Issues

ADB Device Not Found
Kill and restart ADB server
adb kill-server
adb start-server
adb devices

Frida Connection Failed
Check if Frida server is running
adb shell ps | grep frida

Restart Frida server
adb shell "killall frida-server"
adb shell "/data/local/tmp/frida-server &"

Permission Denied Errors
Ensure device is rooted
adb shell su -c "id"

Check file permissions
adb shell ls -la /data/local/tmp/frida-server

SSL Certificate Issues
Install Burp CA certificate
Settings → Security → Install from storage
Select certificate file and install as "CA certificate"

### Performance Optimization

Emulator Performance
Enable hardware acceleration
emulator -avd test_avd -gpu host -memory 4096

Use x86_64 images for better performance
Enable Intel HAXM or AMD-V acceleration

Frida Performance
Use spawning mode for better hook timing
frida -U -f com.example.app -l script.js --no-pause

Disable unnecessary scripts to reduce overhead

## Next Steps

After successful setup:

1. **Read Documentation**: Start with `docs/01-environment-setup.md`
2. **Practice**: Use the included sample scripts and test APKs
3. **Customize**: Modify configuration files for your specific needs
4. **Extend**: Add custom scripts and tools as needed

## Support

For issues and questions:
- Check the troubleshooting section above
- Review the detailed documentation in `docs/`
- Check the project's issue tracker
- Consult the OWASP Mobile Security Testing Guide

## Security Notice

This toolkit is intended for:
- **Educational purposes**
- **Authorized security testing**
- **Research and development**

**Do not use this toolkit for unauthorized activities.** Always ensure you have proper authorization before testing any applications or systems.

Users are responsible for complying with all applicable laws and regulations.
