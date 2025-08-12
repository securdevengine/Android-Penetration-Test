Android Rooting Techniques Guide

This comprehensive guide covers multiple Android rooting methods for security testing and reverse engineering purposes.

Overview

Rooting grants superuser access to Android devices, essential for advanced security testing, reverse engineering, and bypassing protection mechanisms. This guide covers various rooting methods suitable for different scenarios.

Warning and Legal Notice

Rooting your device:
- Voids manufacturer warranty
- May brick your device if done incorrectly
- Can expose security vulnerabilities
- Should only be performed on devices you own
- Use for authorized security testing only

Rooting Method Comparison

Method 1: Magisk (Systemless Root)

Advantages:
- Systemless approach preserves system integrity
- Magisk Hide bypasses root detection
- Large module ecosystem
- SafetyNet bypass capabilities
- Easy to uninstall

Disadvantages:
- Requires unlocked bootloader
- Some apps still detect Magisk
- May need frequent updates

Compatibility:
- Android 5.0+ (API 21+)
- Most devices with unlocked bootloader

Installation Steps:

1. Prerequisites
Check device compatibility:
fastboot devices
fastboot oem device-info

Unlock bootloader (device-specific):
fastboot oem unlock
fastboot flashing unlock

2. Download Magisk
wget https://github.com/topjohnwu/Magisk/releases/latest/download/Magisk-v26.1.apk
adb install Magisk-v26.1.apk

3. Extract and Patch Boot Image
adb shell dd if=/dev/block/bootdevice/by-name/boot of=/sdcard/boot.img
adb pull /sdcard/boot.img

Open Magisk Manager app
Select "Install" > "Select and Patch a File"
Choose the pulled boot.img
Patched image saved as magisk_patched-*.img

4. Flash Patched Boot Image
adb push magisk_patched-*.img /sdcard/
adb reboot bootloader
fastboot flash boot /sdcard/magisk_patched-*.img
fastboot reboot

5. Verify Installation
adb shell su -c "id"
Should return: uid=0(root) gid=0(root)

Method 2: KernelSU (Kernel-level Root)

Advantages:
- Kernel-level implementation
- Better root hiding capabilities
- More powerful than userspace solutions
- Harder to detect by security apps
- Direct kernel module support

Disadvantages:
- Requires custom kernel compilation
- Limited device support
- Complex installation process
- Potential kernel instability

Compatibility:
- Android 10+ (API 29+)
- Devices with kernel source availability
- GKI (Generic Kernel Image) kernels preferred

Installation Steps:

1. Check Kernel Compatibility
adb shell uname -r
adb shell cat /proc/version

2. Download KernelSU
wget https://github.com/tiann/KernelSU/releases/latest/download/KernelSU_<version>.zip

3. Install KernelSU Manager
wget https://github.com/tiann/KernelSU/releases/latest/download/KernelSU_<version>.apk
adb install KernelSU_<version>.apk

4. Flash KernelSU (Method A - Pre-built Kernel)
adb reboot bootloader
fastboot flash boot kernelsu_boot.img
fastboot reboot

5. Flash KernelSU (Method B - Module Installation)
If device supports kernel module loading:
adb push kernelsu.ko /data/local/tmp/
adb shell su -c "insmod /data/local/tmp/kernelsu.ko"

6. Build Custom Kernel (Advanced)
git clone https://github.com/tiann/KernelSU
cd KernelSU
git submodule update --init --recursive

Add to kernel defconfig:
CONFIG_KPROBES=y
CONFIG_HAVE_KPROBES=y
CONFIG_KPROBE_EVENTS=y

Build kernel with KernelSU:
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-android- <device>_defconfig
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-android- -j$(nproc)

7. Verify KernelSU Installation
adb shell su -c "id"
adb shell "su -c 'dmesg | grep kernelsu'"

Method 3: SuperSU (Legacy/Traditional Root)

Note: SuperSU is no longer actively maintained but may work on older devices

Advantages:
- Wide device compatibility
- Stable on older Android versions
- Well-documented

Disadvantages:
- No longer maintained
- Poor SafetyNet bypass
- Vulnerable to detection
- Not recommended for modern devices

Installation Steps:

1. Download SuperSU
wget https://download.chainfire.eu/1220/SuperSU/SR5-SuperSU-v2.82-SR5-20171001224502.zip

2. Flash via Custom Recovery
adb reboot recovery
Flash SuperSU zip in recovery mode

3. Alternative: Install via ADB
adb push SR5-SuperSU-v2.82.zip /sdcard/
adb shell "su -c 'mount -o rw,remount /system'"
adb shell "su -c 'unzip -o /sdcard/SR5-SuperSU-v2.82.zip -d /system/'"

Method 4: One-Click Root Tools

For specific devices and Android versions:

KingRoot:
wget https://kingroot-download.com/kingroot.apk
adb install kingroot.apk

iRoot:
wget http://www.mgyun.com/vroot/iroot.apk
adb install iroot.apk

Framaroot (Old devices):
wget https://framaroot.net/framaroot.apk
adb install framaroot.apk

Note: One-click tools often install potentially unwanted software

Method 5: Exploit-Based Rooting

Device-Specific Exploits:

Samsung Devices:
Odin3 + CF-Auto-Root:
Download CF-Auto-Root for specific model
Flash via Odin3 in Download Mode

LG Devices:
LG Bridge + KDZ firmware modification
Flash modified KDZ with root access

HTC Devices:
HTCDev bootloader unlock + custom recovery
fastboot oem get_identifier_token
Submit token to HTCDev for unlock code

Xiaomi Devices:
Mi Unlock Tool + TWRP + Magisk
Apply for bootloader unlock permission
Use official Mi Unlock Tool

CVE-Based Exploits (Educational):

DirtyCow (CVE-2016-5195):
git clone https://github.com/timwr/CVE-2016-5195
cd CVE-2016-5195
adb push dirtycow /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/dirtycow"
adb shell "/data/local/tmp/dirtycow"

Towelroot (CVE-2014-3153):
wget https://towelroot.com/tr.apk
adb install tr.apk

Method 6: Custom Recovery + Root

TWRP (Team Win Recovery Project):

1. Install TWRP
Download TWRP for device model
fastboot flash recovery twrp.img
fastboot reboot recovery

2. Flash Root Package
Download Magisk/SuperSU zip
Copy to device storage
Flash via TWRP
Reboot system

Orange Fox Recovery:

1. Install Orange Fox
wget https://orangefox.download/<device>/OrangeFox.zip
fastboot flash recovery OrangeFox.img

2. Flash Root Solution
Use Orange Fox interface to flash root packages

Method 7: Temporary Root (No Bootloader Unlock)

Temporary Root via Exploits:

mtk-su (MediaTek devices):
wget https://github.com/diplomatic-platform/mtk-su/releases/latest/download/mtk-su
adb push mtk-su /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/mtk-su"
adb shell "/data/local/tmp/mtk-su"

Temp Root (Various exploits):
git clone https://github.com/android-rooting-tools/android-temp-root
cd android-temp-root
python exploit.py

Method 8: Virtual Device Rooting

Android Emulator (Built-in Root):

1. Create Rooted AVD
avdmanager create avd -n rooted_device -k "system-images;android-30;google_apis;x86_64"
emulator -avd rooted_device -writable-system &

2. Enable Root Access
adb root
adb remount
adb shell "mount -o rw,remount /"

Genymotion (Commercial):

1. Install Genymotion
Download from official website
Create virtual device

2. Root Access
Built-in root access
Install ARM translation if needed

Android-x86 (PC Installation):

1. Install Android-x86
Download ISO from android-x86.org
Install on virtual machine or bare metal

2. Root Access
su command available by default
Full system access

Post-Root Configuration

Root Verification:

1. Basic Root Check
adb shell su -c "id"
adb shell su -c "whoami"

2. Advanced Root Verification
adb shell su -c "mount | grep system"
adb shell su -c "ls -la /system/bin/su"

3. Root App Installation
adb install superuser.apk
adb install rootchecker.apk

Root Hiding and Bypass:

1. Magisk Hide (Magisk only)
Enable Magisk Hide in Magisk Manager
Add target apps to hide list
Rename Magisk Manager app

2. Universal Root Hiding
adb shell su -c "mount -o bind /system/bin/cat /system/bin/su"
adb shell su -c "setprop ro.debuggable 0"
adb shell su -c "setprop ro.secure 1"

3. Build Properties Modification
adb shell su -c "mount -o rw,remount /system"
adb shell su -c "sed -i 's/ro.build.tags=test-keys/ro.build.tags=release-keys/' /system/build.prop"

Security Hardening Post-Root:

1. SELinux Configuration
adb shell su -c "setenforce 1"
adb shell su -c "restorecon -R /system"

2. Permission Management
Install advanced permission manager
Review and restrict root app permissions

3. Regular Updates
Keep root solution updated
Monitor security patches

Troubleshooting Common Issues

Bootloop After Rooting:

1. Recovery Mode Solutions
Boot into recovery mode
Flash original boot.img
fastboot flash boot stock_boot.img

2. Download Mode Recovery
Use manufacturer tools (Odin, LG Bridge, etc.)
Flash stock firmware

3. Fastboot Recovery
fastboot erase userdata
fastboot erase cache
fastboot reboot

Root Detection Issues:

1. SafetyNet Bypass
Use Universal SafetyNet Fix module
Install MagiskHide Props Config

2. Banking App Issues
Use Magisk Hide for specific apps
Install Riru + EdXposed modules

3. Enterprise App Blocking
Use Island app for work profile isolation
Consider temporary root solutions

Device-Specific Considerations

Samsung Devices:
- Knox security affects warranty
- Use Samsung-specific root methods
- ODIN tool required for firmware flashing

Google Pixel:
- Official bootloader unlock supported
- Fastboot commands work reliably
- Regular security updates may break root

OnePlus:
- Developer-friendly unlocking process
- Good custom ROM support
- MSM Download Tool for recovery

Xiaomi:
- Requires official unlock permission
- MIUI-specific modifications needed
- Fastboot commands region-locked

Huawei/Honor:
- Bootloader unlock discontinued
- Limited rooting options for newer devices
- Use older firmware versions if needed

Best Practices and Recommendations

For Security Testing:
1. Use dedicated test devices
2. Prefer Magisk for modern devices
3. Test multiple root methods
4. Document the rooting process
5. Create device backups before rooting

For Reverse Engineering:
1. KernelSU offers deepest access
2. Maintain multiple rooted test devices
3. Use rooted emulators for initial testing
4. Keep root detection bypass tools ready

For Production Use:
1. Never root production devices
2. Use temporary root when possible
3. Understand legal implications
4. Follow corporate security policies

This comprehensive guide covers the major rooting techniques available for Android security testing and reverse engineering. Choose the method that best fits your device, Android version, and security requirements.
