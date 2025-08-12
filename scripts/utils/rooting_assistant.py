#!/usr/bin/env python3

import subprocess
import sys
import os
import requests
import platform
import json
from pathlib import Path
import tempfile
import zipfile

class RootingAssistant:
    def __init__(self):
        self.os_type = platform.system().lower()
        self.device_info = {}
        self.supported_methods = []
        
    def run_command(self, cmd, capture_output=True, timeout=60):
        try:
            if isinstance(cmd, str):
                cmd = cmd.split()
            result = subprocess.run(cmd, capture_output=capture_output, 
                                  text=True, timeout=timeout)
            return result.returncode == 0, result.stdout, result.stderr
        except Exception as e:
            return False, "", str(e)
    
    def detect_device_info(self):
        print("[*] Detecting device information...")
        
        # Basic device info
        success, stdout, _ = self.run_command("adb shell getprop ro.product.model")
        if success:
            self.device_info['model'] = stdout.strip()
        
        success, stdout, _ = self.run_command("adb shell getprop ro.product.brand")
        if success:
            self.device_info['brand'] = stdout.strip()
            
        success, stdout, _ = self.run_command("adb shell getprop ro.build.version.release")
        if success:
            self.device_info['android_version'] = stdout.strip()
            
        success, stdout, _ = self.run_command("adb shell getprop ro.product.cpu.abi")
        if success:
            self.device_info['cpu_arch'] = stdout.strip()
            
        success, stdout, _ = self.run_command("adb shell getprop ro.build.version.sdk")
        if success:
            self.device_info['api_level'] = stdout.strip()
            
        # Check kernel version
        success, stdout, _ = self.run_command("adb shell uname -r")
        if success:
            self.device_info['kernel_version'] = stdout.strip()
            
        # Check bootloader status
        success, stdout, _ = self.run_command("adb shell getprop ro.boot.verifiedbootstate")
        if success:
            self.device_info['bootloader_status'] = stdout.strip()
            
        print(f"[+] Device: {self.device_info.get('brand', 'Unknown')} {self.device_info.get('model', 'Unknown')}")
        print(f"[+] Android: {self.device_info.get('android_version', 'Unknown')} (API {self.device_info.get('api_level', 'Unknown')})")
        print(f"[+] Architecture: {self.device_info.get('cpu_arch', 'Unknown')}")
        print(f"[+] Kernel: {self.device_info.get('kernel_version', 'Unknown')}")
        
    def check_root_status(self):
        print("[*] Checking current root status...")
        
        # Check for existing root
        success, stdout, _ = self.run_command("adb shell which su")
        if success and stdout.strip():
            print("[+] su binary found")
            
            # Test root access
            success, stdout, _ = self.run_command("adb shell su -c id")
            if success and "uid=0" in stdout:
                print("[+] Device is already rooted!")
                return True
            else:
                print("[!] su binary exists but root access denied")
        
        # Check for Magisk
        success, stdout, _ = self.run_command("adb shell pm list packages | grep com.topjohnwu.magisk")
        if success and stdout.strip():
            print("[+] Magisk Manager detected")
            
        # Check for KernelSU
        success, stdout, _ = self.run_command("adb shell pm list packages | grep me.weishu.kernelsu")
        if success and stdout.strip():
            print("[+] KernelSU Manager detected")
            
        # Check for SuperSU
        success, stdout, _ = self.run_command("adb shell pm list packages | grep eu.chainfire.supersu")
        if success and stdout.strip():
            print("[+] SuperSU detected")
            
        print("[!] Device does not appear to be rooted")
        return False
    
    def analyze_rooting_options(self):
        print("[*] Analyzing available rooting methods...")
        
        brand = self.device_info.get('brand', '').lower()
        model = self.device_info.get('model', '').lower()
        android_version = self.device_info.get('android_version', '')
        api_level = int(self.device_info.get('api_level', '0'))
        
        # Magisk compatibility
        if api_level >= 21:  # Android 5.0+
            self.supported_methods.append({
                'name': 'Magisk',
                'difficulty': 'Medium',
                'requirements': ['Unlocked bootloader', 'Custom recovery or fastboot'],
                'advantages': ['Systemless', 'Hide capabilities', 'Module support'],
                'compatibility': 'High'
            })
        
        # KernelSU compatibility  
        if api_level >= 29:  # Android 10+
            self.supported_methods.append({
                'name': 'KernelSU',
                'difficulty': 'Hard',
                'requirements': ['Custom kernel', 'Kernel source availability'],
                'advantages': ['Kernel-level', 'Better hiding', 'Performance'],
                'compatibility': 'Medium'
            })
        
        # Device-specific methods
        if 'samsung' in brand:
            self.supported_methods.append({
                'name': 'CF-Auto-Root',
                'difficulty': 'Easy',
                'requirements': ['Odin3', 'Download mode access'],
                'advantages': ['One-click', 'Samsung-specific'],
                'compatibility': 'High for older devices'
            })
            
        if 'xiaomi' in brand or 'redmi' in brand:
            self.supported_methods.append({
                'name': 'Mi Unlock + Magisk',
                'difficulty': 'Medium',
                'requirements': ['Mi Unlock permission', 'Fastboot'],
                'advantages': ['Official unlock', 'MIUI compatibility'],
                'compatibility': 'High'
            })
            
        # One-click methods for older devices
        if api_level < 23:  # Android 6.0-
            self.supported_methods.append({
                'name': 'KingRoot',
                'difficulty': 'Easy',
                'requirements': ['None'],
                'advantages': ['One-click', 'No unlock needed'],
                'compatibility': 'Medium for old devices'
            })
        
        print(f"[+] Found {len(self.supported_methods)} compatible rooting methods")
        for i, method in enumerate(self.supported_methods, 1):
            print(f"    {i}. {method['name']} (Difficulty: {method['difficulty']})")
    
    def download_magisk(self):
        print("[*] Downloading latest Magisk...")
        
        try:
            # Get latest release info
            response = requests.get("https://api.github.com/repos/topjohnwu/Magisk/releases/latest", timeout=30)
            release_data = response.json()
            
            # Find APK download URL
            apk_url = None
            for asset in release_data['assets']:
                if asset['name'].endswith('.apk'):
                    apk_url = asset['browser_download_url']
                    break
            
            if not apk_url:
                print("[!] Could not find Magisk APK in latest release")
                return False
            
            # Download APK
            print(f"[*] Downloading {apk_url}")
            response = requests.get(apk_url, timeout=120)
            response.raise_for_status()
            
            # Save APK
            magisk_apk = "magisk_latest.apk"
            with open(magisk_apk, 'wb') as f:
                f.write(response.content)
            
            print(f"[+] Magisk downloaded: {magisk_apk}")
            return magisk_apk
            
        except Exception as e:
            print(f"[!] Failed to download Magisk: {e}")
            return False
    
    def download_kernelsu(self):
        print("[*] Downloading latest KernelSU...")
        
        try:
            # Get latest release info
            response = requests.get("https://api.github.com/repos/tiann/KernelSU/releases/latest", timeout=30)
            release_data = response.json()
            
            # Find manager APK
            apk_url = None
            for asset in release_data['assets']:
                if 'manager' in asset['name'].lower() and asset['name'].endswith('.apk'):
                    apk_url = asset['browser_download_url']
                    break
            
            if not apk_url:
                print("[!] Could not find KernelSU Manager APK")
                return False
            
            # Download APK
            response = requests.get(apk_url, timeout=120)
            response.raise_for_status()
            
            # Save APK
            kernelsu_apk = "kernelsu_manager.apk"
            with open(kernelsu_apk, 'wb') as f:
                f.write(response.content)
            
            print(f"[+] KernelSU Manager downloaded: {kernelsu_apk}")
            return kernelsu_apk
            
        except Exception as e:
            print(f"[!] Failed to download KernelSU: {e}")
            return False
    
    def install_magisk_manager(self, apk_path=None):
        if not apk_path:
            apk_path = self.download_magisk()
            if not apk_path:
                return False
        
        print(f"[*] Installing Magisk Manager...")
        success, stdout, stderr = self.run_command(f"adb install {apk_path}")
        
        if success:
            print("[+] Magisk Manager installed successfully")
            return True
        else:
            print(f"[!] Failed to install Magisk Manager: {stderr}")
            return False
    
    def extract_boot_image(self):
        print("[*] Extracting boot image...")
        
        # Try common boot partition paths
        boot_paths = [
            "/dev/block/bootdevice/by-name/boot",
            "/dev/block/by-name/boot", 
            "/dev/block/platform/*/by-name/boot",
            "/dev/block/mmcblk0p*/boot"
        ]
        
        for boot_path in boot_paths:
            print(f"[*] Trying boot path: {boot_path}")
            success, stdout, stderr = self.run_command(f"adb shell ls {boot_path}")
            
            if success:
                print(f"[+] Found boot partition: {boot_path}")
                
                # Extract boot image
                success, _, _ = self.run_command(f"adb shell dd if={boot_path} of=/sdcard/boot.img")
                if success:
                    # Pull to local machine
                    success, _, _ = self.run_command("adb pull /sdcard/boot.img")
                    if success:
                        print("[+] Boot image extracted successfully")
                        return "boot.img"
                    else:
                        print("[!] Failed to pull boot image")
                else:
                    print("[!] Failed to extract boot image")
                break
        
        print("[!] Could not find boot partition")
        return False
    
    def guide_manual_patching(self):
        print("\n" + "="*60)
        print("MANUAL BOOT IMAGE PATCHING GUIDE")
        print("="*60)
        print()
        print("1. Open Magisk Manager app on device")
        print("2. Tap 'Install' button")
        print("3. Select 'Select and Patch a File'")
        print("4. Choose the boot.img file")
        print("5. Wait for patching to complete")
        print("6. Patched file will be saved as magisk_patched-*.img")
        print()
        print("After patching, pull the file:")
        print("adb pull /sdcard/Download/magisk_patched-*.img")
        print()
        print("Then flash it:")
        print("adb reboot bootloader")
        print("fastboot flash boot magisk_patched-*.img")
        print("fastboot reboot")
        print()
        
    def automated_magisk_root(self):
        print("[*] Starting automated Magisk rooting process...")
        
        # Check prerequisites
        success, _, _ = self.run_command("fastboot devices")
        if not success:
            print("[!] Fastboot not available. Ensure device is in fastboot mode.")
            return False
        
        # Download and install Magisk Manager
        if not self.install_magisk_manager():
            return False
        
        # Extract boot image
        boot_img = self.extract_boot_image()
        if not boot_img:
            return False
        
        # Guide user through manual patching
        self.guide_manual_patching()
        
        # Wait for user confirmation
        input("\nPress Enter after you have patched the boot image and pulled it back...")
        
        # Look for patched image
        patched_files = list(Path().glob("magisk_patched-*.img"))
        if not patched_files:
            print("[!] No patched boot image found")
            return False
        
        patched_img = patched_files[0]
        print(f"[+] Found patched image: {patched_img}")
        
        # Flash patched image
        print("[*] Flashing patched boot image...")
        success, _, _ = self.run_command("adb reboot bootloader")
        if success:
            success, _, stderr = self.run_command(f"fastboot flash boot {patched_img}")
            if success:
                print("[+] Patched boot image flashed successfully")
                self.run_command("fastboot reboot")
                print("[+] Device rebooting. Please wait...")
                return True
            else:
                print(f"[!] Failed to flash boot image: {stderr}")
        
        return False
    
    def check_kernelsu_compatibility(self):
        print("[*] Checking KernelSU compatibility...")
        
        # Check kernel version
        success, stdout, _ = self.run_command("adb shell uname -r")
        if not success:
            print("[!] Could not get kernel version")
            return False
        
        kernel_version = stdout.strip()
        print(f"[+] Kernel version: {kernel_version}")
        
        # Check for GKI kernel
        if "android" in kernel_version.lower():
            print("[+] GKI kernel detected - KernelSU compatible")
            return True
        
        # Check kernel configuration
        success, stdout, _ = self.run_command("adb shell cat /proc/config.gz | gunzip | grep CONFIG_KPROBES")
        if success and "CONFIG_KPROBES=y" in stdout:
            print("[+] Kernel supports kprobes - KernelSU compatible")
            return True
        
        print("[!] Kernel may not be compatible with KernelSU")
        print("    Consider using pre-built KernelSU kernel for your device")
        return False
    
    def generate_rooting_report(self):
        print("\n" + "="*60)
        print("ROOTING ANALYSIS REPORT")
        print("="*60)
        
        print(f"\nDevice Information:")
        for key, value in self.device_info.items():
            print(f"  {key.replace('_', ' ').title()}: {value}")
        
        print(f"\nSupported Rooting Methods:")
        for i, method in enumerate(self.supported_methods, 1):
            print(f"\n{i}. {method['name']}")
            print(f"   Difficulty: {method['difficulty']}")
            print(f"   Requirements: {', '.join(method['requirements'])}")
            print(f"   Advantages: {', '.join(method['advantages'])}")
            print(f"   Compatibility: {method['compatibility']}")
        
        print(f"\nRecommendations:")
        if any(method['name'] == 'Magisk' for method in self.supported_methods):
            print("  1. Try Magisk first (most compatible)")
        if any(method['name'] == 'KernelSU' for method in self.supported_methods):
            print("  2. Consider KernelSU for advanced hiding")
        print("  3. Always backup before rooting")
        print("  4. Ensure bootloader is unlockable")
    
    def interactive_rooting_assistant(self):
        print("Android Rooting Assistant")
        print("="*50)
        
        # Check ADB connection
        success, stdout, _ = self.run_command("adb devices")
        if not success or "device" not in stdout:
            print("[!] No Android device detected via ADB")
            print("    Please connect device and enable USB debugging")
            return
        
        # Detect device and analyze options
        self.detect_device_info()
        
        # Check current root status
        if self.check_root_status():
            print("[+] Device is already rooted!")
            return
        
        # Analyze rooting options
        self.analyze_rooting_options()
        
        if not self.supported_methods:
            print("[!] No compatible rooting methods found for this device")
            return
        
        # Generate report
        self.generate_rooting_report()
        
        # Interactive menu
        while True:
            print(f"\nAvailable Actions:")
            print("1. Download Magisk Manager")
            print("2. Download KernelSU Manager") 
            print("3. Automated Magisk rooting")
            print("4. Check KernelSU compatibility")
            print("5. Generate detailed report")
            print("6. Exit")
            
            choice = input("\nSelect option (1-6): ").strip()
            
            if choice == '1':
                self.download_magisk()
            elif choice == '2':
                self.download_kernelsu()
            elif choice == '3':
                self.automated_magisk_root()
            elif choice == '4':
                self.check_kernelsu_compatibility()
            elif choice == '5':
                self.generate_rooting_report()
            elif choice == '6':
                break
            else:
                print("[!] Invalid option")

def main():
    if len(sys.argv) > 1:
        if sys.argv[1] == "--check":
            assistant = RootingAssistant()
            assistant.detect_device_info()
            assistant.check_root_status()
            assistant.analyze_rooting_options()
            assistant.generate_rooting_report()
        elif sys.argv[1] == "--magisk":
            assistant = RootingAssistant()
            assistant.automated_magisk_root()
        elif sys.argv[1] == "--kernelsu":
            assistant = RootingAssistant()
            assistant.check_kernelsu_compatibility()
        else:
            print("Usage: python rooting_assistant.py [--check|--magisk|--kernelsu]")
    else:
        assistant = RootingAssistant()
        assistant.interactive_rooting_assistant()

if __name__ == "__main__":
    main()
