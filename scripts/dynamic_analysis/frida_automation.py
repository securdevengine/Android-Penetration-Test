#!/usr/bin/env python3
"""
Frida Automation Framework

This script provides automated Frida instrumentation and analysis for Android applications.
It handles script loading, data collection, and result analysis with minimal user intervention.
"""

import frida
import sys
import time
import json
import threading
import argparse
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Any
import signal
import os

class FridaAutomation:
    def __init__(self, package_name: str, output_dir: str = None):
        self.package_name = package_name
        self.output_dir = Path(output_dir) if output_dir else Path(f"output/dynamic_analysis/{package_name}")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Frida objects
        self.device = None
        self.session = None
        self.scripts = []
        
        # Data collection
        self.data_collected = {
            'network_requests': [],
            'file_operations': [],
            'crypto_operations': [],
            'api_calls': [],
            'jwt_tokens': [],
            'ssl_bypasses': [],
            'anti_debug_bypasses': [],
            'method_calls': [],
            'system_calls': []
        }
        
        # Configuration
        self.config = {
            'auto_ssl_bypass': True,
            'auto_root_bypass': True,
            'auto_anti_debug_bypass': True,
            'collect_network_data': True,
            'collect_file_operations': True,
            'collect_crypto_data': True,
            'max_data_per_category': 1000,
            'script_timeout': 30
        }
        
        # Script paths
        self.script_dir = Path(__file__).parent.parent.parent / "frida_scripts"
        
        # Default scripts to load
        self.default_scripts = [
            ('ssl_bypass/universal_ssl_bypass.js', 'SSL Bypass'),
            ('anti_debug/universal_bypass.js', 'Anti-Debug Bypass'),
            ('auth_hooks/jwt_hook.js', 'JWT Hook'),
            ('general/network_tracer.js', 'Network Tracer'),
            ('general/file_monitor.js', 'File Monitor'),
            ('general/crypto_logger.js', 'Crypto Logger')
        ]
        
        # Running flag
        self.running = False
        
    def start_monitoring(self, spawn_app: bool = False, load_default_scripts: bool = True) -> bool:
        """Start monitoring the target application"""
        print(f"[+] Starting Frida automation for {self.package_name}")
        
        try:
            # Connect to device
            self.device = frida.get_usb_device()
            print(f"[+] Connected to device: {self.device.name}")
            
            # Attach to or spawn application
            if spawn_app:
                pid = self._spawn_application()
            else:
                pid = self._attach_to_application()
            
            if pid is None:
                print("[-] Failed to attach to application")
                return False
            
            # Load scripts
            if load_default_scripts:
                self._load_default_scripts()
            
            # Start monitoring
            self.running = True
            self._start_monitoring_thread()
            
            print(f"[+] Monitoring started for PID {pid}")
            print("[+] Press Ctrl+C to stop monitoring")
            
            return True
            
        except Exception as e:
            print(f"[-] Error starting monitoring: {e}")
            return False
    
    def _spawn_application(self) -> Optional[int]:
        """Spawn the target application"""
        try:
            print(f"[+] Spawning application: {self.package_name}")
            pid = self.device.spawn([self.package_name])
            self.session = self.device.attach(pid)
            
            # Resume after attaching scripts
            self.device.resume(pid)
            
            return pid
            
        except Exception as e:
            print(f"[-] Failed to spawn application: {e}")
            return None
    
    def _attach_to_application(self) -> Optional[int]:
        """Attach to running application"""
        try:
            # Check if app is running
            processes = self.device.enumerate_processes()
            target_process = None
            
            for process in processes:
                if process.name == self.package_name:
                    target_process = process
                    break
            
            if target_process is None:
                print(f"[-] Application {self.package_name} is not running")
                print("[+] Starting application...")
                
                # Try to start the app
                subprocess.run([
                    'adb', 'shell', 'am', 'start', 
                    '-n', f'{self.package_name}/.MainActivity'
                ], capture_output=True)
                
                # Wait a bit and try again
                time.sleep(3)
                processes = self.device.enumerate_processes()
                for process in processes:
                    if process.name == self.package_name:
                        target_process = process
                        break
                
                if target_process is None:
                    print(f"[-] Could not start application {self.package_name}")
                    return None
            
            print(f"[+] Attaching to process: {target_process.name} (PID: {target_process.pid})")
            self.session = self.device.attach(target_process.pid)
            
            return target_process.pid
            
        except Exception as e:
            print(f"[-] Failed to attach to application: {e}")
            return None
    
    def _load_default_scripts(self):
        """Load default Frida scripts"""
        print("[+] Loading default scripts...")
        
        for script_path, script_name in self.default_scripts:
            full_path = self.script_dir / script_path
            
            if full_path.exists():
                success = self.load_script(str(full_path), script_name)
                if success:
                    print(f"    ✓ {script_name}")
                else:
                    print(f"    ✗ {script_name} (failed)")
            else:
                # Try to create basic script if file doesn't exist
                self._create_basic_script(script_path, script_name)
    
    def _create_basic_script(self, script_path: str, script_name: str):
        """Create basic script if file doesn't exist"""
        script_content = self._get_basic_script_content(script_name)
        if script_content:
            success = self.load_script_content(script_content, script_name)
            if success:
                print(f"    ✓ {script_name} (basic version)")
    
    def _get_basic_script_content(self, script_name: str) -> Optional[str]:
        """Get basic script content for missing scripts"""
        if script_name == "Network Tracer":
            return '''
Java.perform(function() {
    console.log("[+] Basic Network Tracer loaded");
    
    // Hook URL connections
    var URL = Java.use('java.net.URL');
    URL.openConnection.overload().implementation = function() {
        console.log('[+] URL Connection: ' + this.toString());
        send({type: 'network', url: this.toString(), timestamp: Date.now()});
        return this.openConnection();
    };
});
'''
        elif script_name == "File Monitor":
            return '''
Java.perform(function() {
    console.log("[+] Basic File Monitor loaded");
    
    var File = Java.use("java.io.File");
    File.$init.overload("java.lang.String").implementation = function(path) {
        if (path.includes("/data/data/") || path.includes("/sdcard/")) {
            console.log("[+] File access: " + path);
            send({type: 'file', path: path, timestamp: Date.now()});
        }
        return this.$init(path);
    };
});
'''
        elif script_name == "Crypto Logger":
            return '''
Java.perform(function() {
    console.log("[+] Basic Crypto Logger loaded");
    
    try {
        var Cipher = Java.use('javax.crypto.Cipher');
        Cipher.getInstance.overload('java.lang.String').implementation = function(transformation) {
            console.log('[+] Cipher.getInstance: ' + transformation);
            send({type: 'crypto', transformation: transformation, timestamp: Date.now()});
            return this.getInstance(transformation);
        };
    } catch (e) {
        console.log("[-] Failed to hook Cipher: " + e);
    }
});
'''
        return None
    
    def load_script(self, script_path: str, script_name: str = None) -> bool:
        """Load a Frida script from file"""
        try:
            with open(script_path, 'r') as f:
                script_content = f.read()
            
            return self.load_script_content(script_content, script_name or Path(script_path).name)
            
        except Exception as e:
            print(f"[-] Failed to load script {script_path}: {e}")
            return False
    
    def load_script_content(self, script_content: str, script_name: str) -> bool:
        """Load a Frida script from content string"""
        try:
            if not self.session:
                print("[-] No active session")
                return False
            
            script = self.session.create_script(script_content)
            script.on('message', lambda message, data: self._on_message(message, data, script_name))
            script.load()
            
            self.scripts.append({
                'name': script_name,
                'script': script,
                'loaded_at': time.time()
            })
            
            return True
            
        except Exception as e:
            print(f"[-] Failed to load script {script_name}: {e}")
            return False
    
    def _on_message(self, message: Dict, data: Any, script_name: str):
        """Handle messages from Frida scripts"""
        try:
            if message['type'] == 'send':
                payload = message['payload']
                
                # Add metadata
                if isinstance(payload, dict):
                    payload['script_name'] = script_name
                    payload['timestamp'] = time.time()
                
                # Print message
                print(f"[{script_name}] {payload}")
                
                # Categorize and store data
                self._categorize_data(payload)
                
            elif message['type'] == 'error':
                print(f"[Error in {script_name}] {message['stack']}")
                
        except Exception as e:
            print(f"[-] Error handling message from {script_name}: {e}")
    
    def _categorize_data(self, payload: Any):
        """Categorize collected data"""
        if not isinstance(payload, dict):
            return
        
        data_type = payload.get('type', 'unknown')
        
        # Categorize based on type or content
        if data_type == 'network' or 'url' in payload or 'http' in str(payload).lower():
            if len(self.data_collected['network_requests']) < self.config['max_data_per_category']:
                self.data_collected['network_requests'].append(payload)
        
        elif data_type == 'file' or 'path' in payload or 'file' in str(payload).lower():
            if len(self.data_collected['file_operations']) < self.config['max_data_per_category']:
                self.data_collected['file_operations'].append(payload)
        
        elif data_type == 'crypto' or 'cipher' in str(payload).lower() or 'encrypt' in str(payload).lower():
            if len(self.data_collected['crypto_operations']) < self.config['max_data_per_category']:
                self.data_collected['crypto_operations'].append(payload)
        
        elif 'jwt' in str(payload).lower() or 'token' in str(payload).lower():
            if len(self.data_collected['jwt_tokens']) < self.config['max_data_per_category']:
                self.data_collected['jwt_tokens'].append(payload)
        
        elif 'ssl' in str(payload).lower() or 'certificate' in str(payload).lower():
            if len(self.data_collected['ssl_bypasses']) < self.config['max_data_per_category']:
                self.data_collected['ssl_bypasses'].append(payload)
        
        elif 'debug' in str(payload).lower() or 'bypass' in str(payload).lower():
            if len(self.data_collected['anti_debug_bypasses']) < self.config['max_data_per_category']:
                self.data_collected['anti_debug_bypasses'].append(payload)
        
        else:
            if len(self.data_collected['api_calls']) < self.config['max_data_per_category']:
                self.data_collected['api_calls'].append(payload)
    
    def _start_monitoring_thread(self):
        """Start background monitoring thread"""
        def monitor_thread():
            while self.running:
                try:
                    # Check if session is still alive
                    if self.session:
                        # Periodic health check
                        pass
                    
                    time.sleep(5)  # Check every 5 seconds
                    
                except Exception as e:
                    print(f"[-] Monitoring thread error: {e}")
                    break
        
        thread = threading.Thread(target=monitor_thread, daemon=True)
        thread.start()
    
    def wait_for_user_interrupt(self):
        """Wait for user to interrupt monitoring"""
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[+] Stopping monitoring...")
            self.stop_monitoring()
    
    def stop_monitoring(self):
        """Stop monitoring and generate reports"""
        self.running = False
        
        print("[+] Generating analysis report...")
        report = self.generate_report()
        
        # Save reports
        self._save_reports(report)
        
        # Cleanup
        self._cleanup()
        
        print(f"[+] Analysis complete. Results saved to {self.output_dir}")
    
    def generate_report(self) -> Dict:
        """Generate comprehensive analysis report"""
        total_data = sum(len(data) for data in self.data_collected.values())
        
        report = {
            'package_name': self.package_name,
            'analysis_start_time': getattr(self, 'start_time', time.time()),
            'analysis_end_time': time.time(),
            'scripts_loaded': len(self.scripts),
            'total_data_points': total_data,
            'summary': {
                'network_requests': len(self.data_collected['network_requests']),
                'file_operations': len(self.data_collected['file_operations']),
                'crypto_operations': len(self.data_collected['crypto_operations']),
                'jwt_tokens': len(self.data_collected['jwt_tokens']),
                'ssl_bypasses': len(self.data_collected['ssl_bypasses']),
                'anti_debug_bypasses': len(self.data_collected['anti_debug_bypasses']),
                'api_calls': len(self.data_collected['api_calls'])
            },
            'data_collected': self.data_collected,
            'scripts_info': [
                {
                    'name': script['name'],
                    'loaded_at': script['loaded_at']
                } for script in self.scripts
            ]
        }
        
        return report
    
    def _save_reports(self, report: Dict):
        """Save analysis reports in multiple formats"""
        # Save JSON report
        json_report_file = self.output_dir / 'frida_analysis_report.json'
        with open(json_report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        # Save summary report
        summary_file = self.output_dir / 'analysis_summary.txt'
        with open(summary_file, 'w') as f:
            f.write(f"Frida Dynamic Analysis Summary\n")
            f.write(f"{'='*40}\n\n")
            f.write(f"Package: {report['package_name']}\n")
            f.write(f"Analysis Duration: {report['analysis_end_time'] - report['analysis_start_time']:.2f} seconds\n")
            f.write(f"Scripts Loaded: {report['scripts_loaded']}\n")
            f.write(f"Total Data Points: {report['total_data_points']}\n\n")
            
            f.write("Summary by Category:\n")
            f.write("-" * 20 + "\n")
            for category, count in report['summary'].items():
                f.write(f"{category.replace('_', ' ').title()}: {count}\n")
            
            f.write(f"\nDetailed findings saved to: {json_report_file}\n")
        
        # Save network activity log
        if report['data_collected']['network_requests']:
            network_file = self.output_dir / 'network_activity.log'
            with open(network_file, 'w') as f:
                for req in report['data_collected']['network_requests']:
                    f.write(f"{req.get('timestamp', 'N/A')} - {req.get('url', 'N/A')}\n")
        
        # Save crypto operations log
        if report['data_collected']['crypto_operations']:
            crypto_file = self.output_dir / 'crypto_operations.log'
            with open(crypto_file, 'w') as f:
                for op in report['data_collected']['crypto_operations']:
                    f.write(f"{op.get('timestamp', 'N/A')} - {op.get('transformation', 'N/A')}\n")
    
    def _cleanup(self):
        """Cleanup Frida resources"""
        try:
            # Unload scripts
            for script_info in self.scripts:
                try:
                    script_info['script'].unload()
                except:
                    pass
            
            # Detach session
            if self.session:
                try:
                    self.session.detach()
                except:
                    pass
            
            print("[+] Cleanup complete")
            
        except Exception as e:
            print(f"[-] Cleanup error: {e}")
    
    def add_custom_script(self, script_content: str, script_name: str) -> bool:
        """Add a custom script during runtime"""
        return self.load_script_content(script_content, script_name)
    
    def get_data_summary(self) -> Dict:
        """Get current data collection summary"""
        return {
            'total_data_points': sum(len(data) for data in self.data_collected.values()),
            'by_category': {
                category: len(data) for category, data in self.data_collected.items()
            }
        }


def main():
    parser = argparse.ArgumentParser(description='Automated Frida instrumentation for Android applications')
    parser.add_argument('package_name', help='Android package name to analyze')
    parser.add_argument('-o', '--output', help='Output directory for results')
    parser.add_argument('-s', '--spawn', action='store_true', help='Spawn the application instead of attaching')
    parser.add_argument('--no-default-scripts', action='store_true', help='Do not load default scripts')
    parser.add_argument('--script', action='append', help='Additional script file to load')
    parser.add_argument('--timeout', type=int, default=0, help='Stop analysis after N seconds (0 = infinite)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    try:
        # Create automation instance
        automation = FridaAutomation(args.package_name, args.output)
        automation.start_time = time.time()
        
        # Start monitoring
        success = automation.start_monitoring(
            spawn_app=args.spawn,
            load_default_scripts=not args.no_default_scripts
        )
        
        if not success:
            print("[-] Failed to start monitoring")
            sys.exit(1)
        
        # Load additional scripts
        if args.script:
            for script_file in args.script:
                automation.load_script(script_file)
        
        # Set up timeout if specified
        if args.timeout > 0:
            def timeout_handler():
                time.sleep(args.timeout)
                automation.stop_monitoring()
            
            timeout_thread = threading.Thread(target=timeout_handler, daemon=True)
            timeout_thread.start()
        
        # Wait for user interrupt or timeout
        automation.wait_for_user_interrupt()
        
    except KeyboardInterrupt:
        print("\n[+] Analysis interrupted by user")
    except Exception as e:
        print(f"[-] Analysis failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
