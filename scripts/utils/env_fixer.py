#!/usr/bin/env python3

import subprocess
import sys
import os
import argparse
import platform
import time
try:
    import requests
except ImportError:  # pragma: no cover - runtime download dependency
    requests = None
import zipfile
from pathlib import Path

class EnvironmentFixer:
    def __init__(self):
        self.os_type = platform.system().lower()
        self.fixes_applied = []
        self.errors_encountered = []
        
    def run_command(self, cmd, capture_output=True, timeout=60):
        try:
            if isinstance(cmd, str):
                cmd = cmd.split()
            result = subprocess.run(cmd, capture_output=capture_output, 
                                  text=True, timeout=timeout)
            return result.returncode == 0, result.stdout, result.stderr
        except Exception as e:
            return False, "", str(e)
    
    def fix_adb_issues(self):
        print("[*] Fixing ADB issues...")
        
        # Kill and restart ADB server
        self.run_command("adb kill-server")
        time.sleep(2)
        
        # Kill any processes using ADB port
        if self.os_type == "linux":
            self.run_command("sudo fuser -k 5037/tcp")
        elif self.os_type == "windows":
            success, stdout, _ = self.run_command("netstat -ano | findstr :5037")
            if success:
                for line in stdout.split('\n'):
                    if ':5037' in line:
                        pid = line.split()[-1]
                        self.run_command(f"taskkill /PID {pid} /F")
        
        # Start ADB server
        success, _, _ = self.run_command("adb start-server")
        if success:
            self.fixes_applied.append("Restarted ADB server")
            time.sleep(3)
            
            # Check devices
            success, stdout, _ = self.run_command("adb devices")
            if success:
                devices = [line for line in stdout.split('\n') if '\tdevice' in line]
                if devices:
                    print(f"[+] Found {len(devices)} device(s) after ADB restart")
                    return True
        
        return False
    
    def fix_device_authorization(self):
        print("[*] Fixing device authorization...")
        
        # Clear ADB keys
        adb_dir = Path.home() / ".android"
        if adb_dir.exists():
            for key_file in adb_dir.glob("adbkey*"):
                try:
                    key_file.unlink()
                    print(f"[+] Removed {key_file}")
                except Exception as e:
                    print(f"[!] Failed to remove {key_file}: {e}")
        
        # Restart ADB
        self.run_command("adb kill-server")
        time.sleep(2)
        self.run_command("adb start-server")
        time.sleep(2)
        
        print("[+] Please accept the RSA fingerprint on your device")
        time.sleep(5)
        
        success, stdout, _ = self.run_command("adb devices")
        if success:
            authorized_devices = [line for line in stdout.split('\n') if '\tdevice' in line]
            if authorized_devices:
                self.fixes_applied.append("Fixed device authorization")
                return True
        
        return False
    
    def fix_frida_server(self):
        print("[*] Fixing Frida server issues...")
        
        # Kill existing Frida server
        self.run_command("adb shell su -c 'killall frida-server'")
        time.sleep(2)
        
        # Check if Frida server exists
        success, _, _ = self.run_command("adb shell ls /data/local/tmp/frida-server")
        if not success:
            print("[!] Frida server not found on device")
            return False
        
        # Set permissions and start
        self.run_command("adb shell su -c 'chmod 755 /data/local/tmp/frida-server'")
        self.run_command("adb shell su -c '/data/local/tmp/frida-server &'")
        time.sleep(3)
        
        # Verify it's running
        success, stdout, _ = self.run_command("adb shell ps | grep frida")
        if success and "frida-server" in stdout:
            self.fixes_applied.append("Started Frida server")
            
            # Set up port forwarding
            self.run_command("adb forward tcp:27042 tcp:27042")
            self.fixes_applied.append("Set up Frida port forwarding")
            return True
        
        return False
    
    def fix_network_issues(self):
        print("[*] Fixing network issues...")
        
        # Reset network settings
        self.run_command("adb shell settings delete global http_proxy")
        self.run_command("adb shell settings delete global https_proxy")
        
        # Set up basic proxy if needed
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex(('127.0.0.1', 8080))
            sock.close()
            
            if result == 0:
                # Burp is running, set up proxy
                host_ip = self.get_host_ip()
                if host_ip:
                    self.run_command(f"adb shell settings put global http_proxy {host_ip}:8080")
                    self.fixes_applied.append(f"Set HTTP proxy to {host_ip}:8080")
        except Exception as e:
            print(f"[!] Network fix error: {e}")
        
        return True
    
    def get_host_ip(self):
        try:
            # Get host IP that device can reach
            success, stdout, _ = self.run_command("adb shell ip route get 8.8.8.8")
            if success:
                # Extract IP from route output
                import re
                match = re.search(r'src (\d+\.\d+\.\d+\.\d+)', stdout)
                if match:
                    return match.group(1)
            
            # Fallback methods
            success, stdout, _ = self.run_command("adb shell ifconfig wlan0")
            if success:
                import re
                match = re.search(r'inet addr:(\d+\.\d+\.\d+\.\d+)', stdout)
                if match:
                    # Get host IP in same subnet
                    device_ip = match.group(1)
                    subnet = '.'.join(device_ip.split('.')[:-1])
                    return f"{subnet}.1"  # Common gateway IP
        except Exception:
            pass
        
        return "192.168.1.100"  # Default fallback
    
    def fix_environment_variables(self):
        print("[*] Fixing environment variables...")
        
        # Find Android SDK
        possible_sdk_paths = [
            Path.home() / "Android" / "Sdk",
            Path("/opt/android-sdk"),
            Path("/usr/local/android-sdk"),
            Path("C:/Users") / os.getenv('USERNAME', '') / "AppData/Local/Android/Sdk" if self.os_type == "windows" else None
        ]
        
        sdk_path = None
        for path in possible_sdk_paths:
            if path and path.exists():
                sdk_path = str(path)
                break
        
        if sdk_path:
            # Create environment setup script
            if self.os_type == "windows":
                env_script = "set_android_env.bat"
                env_content = f"""@echo off
set ANDROID_HOME={sdk_path}
set PATH=%PATH%;%ANDROID_HOME%\\platform-tools;%ANDROID_HOME%\\tools
echo Android environment variables set
"""
            else:
                env_script = "set_android_env.sh"
                env_content = f"""#!/bin/bash
export ANDROID_HOME="{sdk_path}"
export PATH="$PATH:$ANDROID_HOME/platform-tools:$ANDROID_HOME/tools"
echo "Android environment variables set"
"""
            
            with open(env_script, 'w') as f:
                f.write(env_content)
            
            if not self.os_type == "windows":
                os.chmod(env_script, 0o755)
            
            print(f"[+] Created {env_script}")
            self.fixes_applied.append(f"Created environment setup script: {env_script}")
            
            # Add to shell profile
            if not self.os_type == "windows":
                shell_profile = Path.home() / ".bashrc"
                if not shell_profile.exists():
                    shell_profile = Path.home() / ".profile"
                
                env_line = f'export ANDROID_HOME="{sdk_path}"\nexport PATH="$PATH:$ANDROID_HOME/platform-tools:$ANDROID_HOME/tools"\n'
                
                try:
                    with open(shell_profile, 'a') as f:
                        f.write(f"\n# Android SDK environment\n{env_line}")
                    self.fixes_applied.append(f"Added Android environment to {shell_profile}")
                except Exception as e:
                    print(f"[!] Could not write to {shell_profile}: {e}")
        
        return True
    
    def fix_usb_issues(self):
        print("[*] Fixing USB connection issues...")
        
        if self.os_type == "linux":
            # Create udev rules for Android devices
            udev_rules = """# Android USB rules
SUBSYSTEM=="usb", ATTR{idVendor}=="18d1", MODE="0666", GROUP="plugdev"
SUBSYSTEM=="usb", ATTR{idVendor}=="04e8", MODE="0666", GROUP="plugdev"
SUBSYSTEM=="usb", ATTR{idVendor}=="0bb4", MODE="0666", GROUP="plugdev"
SUBSYSTEM=="usb", ATTR{idVendor}=="1004", MODE="0666", GROUP="plugdev"
SUBSYSTEM=="usb", ATTR{idVendor}=="22b8", MODE="0666", GROUP="plugdev"
SUBSYSTEM=="usb", ATTR{idVendor}=="12d1", MODE="0666", GROUP="plugdev"
"""
            try:
                with open("/tmp/51-android.rules", 'w') as f:
                    f.write(udev_rules)
                
                success, _, _ = self.run_command("sudo cp /tmp/51-android.rules /etc/udev/rules.d/")
                if success:
                    self.run_command("sudo udevadm control --reload-rules")
                    self.run_command("sudo udevadm trigger")
                    self.fixes_applied.append("Added Android USB udev rules")
            except Exception as e:
                print(f"[!] Failed to add udev rules: {e}")
        
        return True
    
    def download_frida_server(self):
        print("[*] Downloading Frida server...")
        
        # Get device architecture
        success, stdout, _ = self.run_command("adb shell getprop ro.product.cpu.abi")
        if not success:
            print("[!] Could not determine device architecture")
            return False
        
        arch = stdout.strip()
        arch_map = {
            "arm64-v8a": "arm64",
            "armeabi-v7a": "arm",
            "x86": "x86",
            "x86_64": "x86_64"
        }
        
        frida_arch = arch_map.get(arch, "arm64")
        frida_version = "16.1.4"  # Latest stable version
        
        url = f"https://github.com/frida/frida/releases/download/{frida_version}/frida-server-{frida_version}-android-{frida_arch}.xz"
        
        try:
            print(f"[*] Downloading Frida server for {arch} ({frida_arch})...")
            response = requests.get(url, timeout=60)
            response.raise_for_status()
            
            # Save and extract
            frida_file = f"frida-server-{frida_version}-android-{frida_arch}.xz"
            with open(frida_file, 'wb') as f:
                f.write(response.content)
            
            # Extract using Python lzma
            import lzma
            with lzma.open(frida_file, 'rb') as f_in:
                with open('frida-server', 'wb') as f_out:
                    f_out.write(f_in.read())
            
            # Push to device
            success, _, _ = self.run_command("adb push frida-server /data/local/tmp/")
            if success:
                self.run_command("adb shell su -c 'chmod 755 /data/local/tmp/frida-server'")
                print("[+] Frida server installed successfully")
                self.fixes_applied.append("Downloaded and installed Frida server")
                
                # Clean up
                os.remove(frida_file)
                os.remove('frida-server')
                return True
            
        except Exception as e:
            print(f"[!] Failed to download Frida server: {e}")
        
        return False
    
    def verify_fixes(self):
        print("\n[*] Verifying applied fixes...")
        
        # Check ADB
        success, stdout, _ = self.run_command("adb devices")
        if success:
            devices = [line for line in stdout.split('\n') if '\tdevice' in line]
            if devices:
                print(f"[+] ADB: {len(devices)} device(s) connected")
            else:
                print("[!] ADB: No devices found")
        
        # Check Frida
        success, _, _ = self.run_command("frida-ps -U")
        if success:
            print("[+] Frida: Connection successful")
        else:
            print("[!] Frida: Connection failed")
        
        # Check basic tools
        tools = ["jadx", "apktool", "python3"]
        for tool in tools:
            success, _, _ = self.run_command(f"{tool} --version")
            if success:
                print(f"[+] {tool}: Available")
            else:
                print(f"[!] {tool}: Not available")
    
    def run_comprehensive_fix(self):
        print("Android Environment Comprehensive Fixer")
        print("=" * 60)
        
        # Run fixes in order
        fixes = [
            ("ADB Issues", self.fix_adb_issues),
            ("Device Authorization", self.fix_device_authorization),
            ("USB Issues", self.fix_usb_issues),
            ("Environment Variables", self.fix_environment_variables),
            ("Frida Server", self.fix_frida_server),
            ("Network Issues", self.fix_network_issues)
        ]
        
        for fix_name, fix_func in fixes:
            try:
                print(f"\n[*] Applying {fix_name} fixes...")
                success = fix_func()
                if success:
                    print(f"[+] {fix_name} fixes applied successfully")
                else:
                    print(f"[!] {fix_name} fixes failed or not needed")
            except Exception as e:
                print(f"[!] Error in {fix_name} fix: {e}")
                self.errors_encountered.append(f"{fix_name}: {e}")
        
        # Special case: Download Frida server if needed
        success, _, _ = self.run_command("adb shell ls /data/local/tmp/frida-server")
        if not success:
            print("\n[*] Frida server not found, attempting download...")
            self.download_frida_server()
        
        # Verify all fixes
        self.verify_fixes()
        
        # Generate report
        print("\n" + "=" * 60)
        print("FIX REPORT")
        print("=" * 60)
        
        if self.fixes_applied:
            print(f"[+] Applied {len(self.fixes_applied)} fix(es):")
            for i, fix in enumerate(self.fixes_applied, 1):
                print(f"    {i}. {fix}")
        
        if self.errors_encountered:
            print(f"\n[!] Encountered {len(self.errors_encountered)} error(s):")
            for i, error in enumerate(self.errors_encountered, 1):
                print(f"    {i}. {error}")
        
        if not self.fixes_applied and not self.errors_encountered:
            print("[*] No fixes needed - environment appears to be working")
        
        print("\n[*] Run diagnostic_tool.py to verify all fixes")

def main():
    parser = argparse.ArgumentParser(description="Repair common Android testing environment issues")
    parser.parse_args()

    if requests is None:
        print("[-] The 'requests' package is required. Install it with: pip install requests")
        sys.exit(1)

    if os.geteuid() == 0 if hasattr(os, 'geteuid') else False:
        print("[!] Do not run this script as root/administrator")
        sys.exit(1)
    
    fixer = EnvironmentFixer()
    fixer.run_comprehensive_fix()

if __name__ == "__main__":
    main()
