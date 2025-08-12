#!/usr/bin/env python3

import subprocess
import sys
import os
import platform
import socket
import time
from pathlib import Path

class AndroidDiagnosticTool:
    def __init__(self):
        self.issues_found = []
        self.fixes_applied = []
        self.os_type = platform.system().lower()
        
    def run_command(self, cmd, capture_output=True, timeout=30):
        try:
            if isinstance(cmd, str):
                cmd = cmd.split()
            result = subprocess.run(cmd, capture_output=capture_output, 
                                  text=True, timeout=timeout)
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, "", "Command timed out"
        except Exception as e:
            return False, "", str(e)
    
    def check_adb_installation(self):
        print("[*] Checking ADB installation...")
        success, stdout, stderr = self.run_command("adb version")
        
        if not success:
            self.issues_found.append("ADB not installed or not in PATH")
            return False
        
        print(f"[+] ADB found: {stdout.split()[4] if len(stdout.split()) > 4 else 'Unknown version'}")
        return True
    
    def check_adb_server(self):
        print("[*] Checking ADB server status...")
        success, stdout, stderr = self.run_command("adb devices")
        
        if "daemon not running" in stderr:
            print("[!] ADB daemon not running, starting...")
            self.run_command("adb start-server")
            time.sleep(2)
            success, stdout, stderr = self.run_command("adb devices")
        
        if not success:
            self.issues_found.append("ADB server failed to start")
            return False
        
        devices = [line for line in stdout.split('\n') if '\tdevice' in line]
        if not devices:
            self.issues_found.append("No Android devices detected")
            return False
        
        print(f"[+] Found {len(devices)} device(s)")
        return True
    
    def check_device_connection(self):
        print("[*] Checking device connection details...")
        success, stdout, stderr = self.run_command("adb devices -l")
        
        if not success:
            return False
        
        for line in stdout.split('\n'):
            if '\tdevice' in line:
                print(f"[+] Device: {line}")
                
                # Check if device is rooted
                root_success, root_out, _ = self.run_command("adb shell su -c id")
                if root_success and "uid=0" in root_out:
                    print("[+] Device is rooted")
                else:
                    print("[!] Device not rooted or root access denied")
                    self.issues_found.append("Device not rooted")
        
        return True
    
    def check_frida_installation(self):
        print("[*] Checking Frida installation...")
        
        # Check Frida CLI
        success, stdout, stderr = self.run_command("frida --version")
        if not success:
            self.issues_found.append("Frida not installed")
            return False
        
        print(f"[+] Frida CLI version: {stdout.strip()}")
        
        # Check frida-tools
        success, stdout, stderr = self.run_command("frida-ps --version")
        if success:
            print(f"[+] frida-tools version: {stdout.strip()}")
        
        return True
    
    def check_frida_server(self):
        print("[*] Checking Frida server on device...")
        
        # Check if Frida server is running
        success, stdout, stderr = self.run_command("adb shell ps | grep frida")
        
        if not success or "frida-server" not in stdout:
            print("[!] Frida server not running")
            
            # Check if Frida server exists
            success, stdout, stderr = self.run_command("adb shell ls /data/local/tmp/frida-server")
            if not success:
                self.issues_found.append("Frida server not installed on device")
                return False
            
            # Try to start Frida server
            print("[*] Attempting to start Frida server...")
            self.run_command("adb shell su -c 'chmod 755 /data/local/tmp/frida-server'")
            self.run_command("adb shell su -c '/data/local/tmp/frida-server &'")
            time.sleep(3)
            
            # Check again
            success, stdout, stderr = self.run_command("adb shell ps | grep frida")
            if success and "frida-server" in stdout:
                print("[+] Frida server started successfully")
                self.fixes_applied.append("Started Frida server")
            else:
                self.issues_found.append("Failed to start Frida server")
                return False
        else:
            print("[+] Frida server is running")
        
        return True
    
    def check_frida_connection(self):
        print("[*] Testing Frida connection...")
        
        success, stdout, stderr = self.run_command("frida-ps -U")
        if not success:
            self.issues_found.append("Cannot connect to Frida server")
            
            # Try port forwarding
            print("[*] Attempting port forwarding...")
            self.run_command("adb forward tcp:27042 tcp:27042")
            time.sleep(1)
            
            success, stdout, stderr = self.run_command("frida-ps -U")
            if success:
                print("[+] Port forwarding fixed the issue")
                self.fixes_applied.append("Applied ADB port forwarding")
            else:
                return False
        
        print("[+] Frida connection successful")
        return True
    
    def check_network_setup(self):
        print("[*] Checking network configuration...")
        
        # Check proxy settings
        success, stdout, stderr = self.run_command("adb shell settings get global http_proxy")
        if success and stdout.strip():
            print(f"[+] HTTP proxy configured: {stdout.strip()}")
        else:
            print("[*] No HTTP proxy configured")
        
        # Check if Burp Suite is accessible
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex(('127.0.0.1', 8080))
            sock.close()
            
            if result == 0:
                print("[+] Burp Suite proxy accessible on 127.0.0.1:8080")
            else:
                print("[!] Burp Suite proxy not accessible")
        except Exception as e:
            print(f"[!] Network check failed: {e}")
        
        return True
    
    def check_tools_availability(self):
        print("[*] Checking reverse engineering tools...")
        
        tools = {
            'jadx': 'jadx --version',
            'apktool': 'apktool --version',
            'aapt': 'aapt version',
            'keytool': 'keytool -help',
            'python3': 'python3 --version',
            'java': 'java -version'
        }
        
        for tool, cmd in tools.items():
            success, stdout, stderr = self.run_command(cmd)
            if success:
                version = stdout.split('\n')[0] if stdout else stderr.split('\n')[0]
                print(f"[+] {tool}: {version}")
            else:
                print(f"[!] {tool}: Not found")
                self.issues_found.append(f"{tool} not installed")
        
        return True
    
    def check_environment_variables(self):
        print("[*] Checking environment variables...")
        
        android_home = os.environ.get('ANDROID_HOME')
        if android_home:
            print(f"[+] ANDROID_HOME: {android_home}")
            if not Path(android_home).exists():
                print(f"[!] ANDROID_HOME path does not exist: {android_home}")
                self.issues_found.append("ANDROID_HOME path invalid")
        else:
            print("[!] ANDROID_HOME not set")
            self.issues_found.append("ANDROID_HOME not set")
        
        # Check PATH for Android tools
        path = os.environ.get('PATH', '')
        if 'platform-tools' in path:
            print("[+] Android platform-tools in PATH")
        else:
            print("[!] Android platform-tools not in PATH")
            self.issues_found.append("Android tools not in PATH")
        
        return True
    
    def fix_common_issues(self):
        print("\n[*] Attempting to fix common issues...")
        
        # Reset ADB
        if "ADB server failed to start" in self.issues_found:
            print("[*] Resetting ADB...")
            self.run_command("adb kill-server")
            time.sleep(2)
            self.run_command("adb start-server")
            time.sleep(2)
            
            success, _, _ = self.run_command("adb devices")
            if success:
                self.fixes_applied.append("Reset ADB server")
        
        # Kill conflicting processes
        if self.os_type == "linux" or self.os_type == "darwin":
            self.run_command("pkill -f frida")
            self.run_command("sudo fuser -k 5037/tcp")
        
        # Set basic environment variables
        if "ANDROID_HOME not set" in self.issues_found:
            possible_paths = [
                os.path.expanduser("~/Android/Sdk"),
                "/opt/android-sdk",
                "/usr/local/android-sdk"
            ]
            
            for path in possible_paths:
                if Path(path).exists():
                    os.environ['ANDROID_HOME'] = path
                    os.environ['PATH'] = f"{os.environ['PATH']}:{path}/platform-tools:{path}/tools"
                    print(f"[+] Set ANDROID_HOME to {path}")
                    self.fixes_applied.append(f"Set ANDROID_HOME to {path}")
                    break
    
    def generate_report(self):
        print("\n" + "="*60)
        print("DIAGNOSTIC REPORT")
        print("="*60)
        
        if not self.issues_found:
            print("[+] No issues found! Environment is ready for Android reverse engineering.")
        else:
            print(f"[!] Found {len(self.issues_found)} issue(s):")
            for i, issue in enumerate(self.issues_found, 1):
                print(f"    {i}. {issue}")
        
        if self.fixes_applied:
            print(f"\n[+] Applied {len(self.fixes_applied)} fix(es):")
            for i, fix in enumerate(self.fixes_applied, 1):
                print(f"    {i}. {fix}")
        
        print("\n" + "="*60)
        
        # Generate suggestions
        if self.issues_found:
            print("\nSUGGESTED ACTIONS:")
            
            if "ADB not installed" in self.issues_found:
                print("- Install Android SDK Platform Tools")
                print("  Ubuntu: sudo apt install android-tools-adb")
                print("  macOS: brew install android-platform-tools")
            
            if "No Android devices detected" in self.issues_found:
                print("- Connect Android device via USB")
                print("- Enable USB Debugging in Developer Options")
                print("- Accept RSA fingerprint on device")
            
            if "Device not rooted" in self.issues_found:
                print("- Root device using Magisk or similar")
                print("- Or use Android emulator with root access")
            
            if "Frida not installed" in self.issues_found:
                print("- Install Frida: pip install frida-tools")
                print("- Download Frida server for device architecture")
            
            if "Frida server not installed on device" in self.issues_found:
                print("- Download correct Frida server from GitHub releases")
                print("- Push to device: adb push frida-server /data/local/tmp/")
                print("- Set permissions: adb shell chmod 755 /data/local/tmp/frida-server")
    
    def run_full_diagnostic(self):
        print("Android Reverse Engineering Environment Diagnostic Tool")
        print("="*60)
        
        # Run all checks
        checks = [
            self.check_adb_installation,
            self.check_adb_server,
            self.check_device_connection,
            self.check_frida_installation,
            self.check_frida_server,
            self.check_frida_connection,
            self.check_network_setup,
            self.check_tools_availability,
            self.check_environment_variables
        ]
        
        for check in checks:
            try:
                check()
            except Exception as e:
                print(f"[!] Check failed: {e}")
                self.issues_found.append(f"Diagnostic error: {e}")
            print()
        
        # Attempt fixes
        if self.issues_found:
            self.fix_common_issues()
        
        # Generate final report
        self.generate_report()
        
        return len(self.issues_found) == 0

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--fix":
        print("[*] Running diagnostic with automatic fixes...")
        fix_mode = True
    else:
        print("[*] Running diagnostic in check-only mode...")
        print("[*] Use --fix flag to attempt automatic fixes")
        fix_mode = False
    
    diagnostic = AndroidDiagnosticTool()
    success = diagnostic.run_full_diagnostic()
    
    if success:
        print("\n[+] Environment is ready for Android reverse engineering!")
        sys.exit(0)
    else:
        print("\n[!] Issues found. Please address them before proceeding.")
        sys.exit(1)

if __name__ == "__main__":
    main()
