#!/usr/bin/env python3
"""
Frida Automation Framework

This script provides automated Frida instrumentation and analysis for Android applications.
It handles script loading, data collection, and result analysis with minimal user intervention.
"""

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

# frida is only needed to actually attach to a device. Import it lazily so the
# module (and its offline report/redaction logic) can be imported and tested
# without the frida package or a connected device present.
try:
    import frida
except ImportError:  # pragma: no cover - exercised only where frida is absent
    frida = None

# Bootstrap the shared safety/control layer (scripts/core).
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.roe import RulesOfEngagement  # noqa: E402
from core.evidence import EvidenceStore, AuditLog, redact  # noqa: E402

# Capability status for each instrumentation hook.
AVAILABLE = "AVAILABLE"   # real script file loaded
DEGRADED = "DEGRADED"     # missing file; limited generated substitute used
FAILED = "FAILED"         # missing and no substitute, or load error


class FridaAutomation:
    def __init__(self, package_name: str, output_dir: str = None,
                 roe: "RulesOfEngagement" = None, evidence: "EvidenceStore" = None,
                 audit: "AuditLog" = None, reveal_raw: bool = False):
        self.package_name = package_name
        self.output_dir = Path(output_dir) if output_dir else Path(f"output/dynamic_analysis/{package_name}")
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Safety layer.
        self.roe = roe
        self.evidence = evidence
        self.audit = audit
        self.reveal_raw = reveal_raw

        # Frida objects
        self.device = None
        self.session = None
        self.scripts = []

        # Per-hook capability status (fail-honest reporting, #7).
        self.capabilities: Dict[str, str] = {}
        # Bounded-queue drop counters + monotonic sequence (#12).
        self.dropped_events: Dict[str, int] = {}
        self._seq = 0
        
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

        # Fail closed: the package must be authorized before instrumenting it.
        if self.roe is not None:
            self.roe.check_kill_switch()
            self.roe.require_package(self.package_name)
            if self.audit:
                self.audit.record('frida_start', {'package': self.package_name})

        if frida is None:
            print("[-] The 'frida' package is not installed; cannot attach to a device.")
            return False

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
        """Load default Frida scripts, tracking capability status (#7).

        A missing script is not silently swapped for a limited generated hook
        and reported as success. Each capability is recorded as AVAILABLE
        (real file), DEGRADED (generated substitute - partial coverage), or
        FAILED (no substitute / load error) so operators never believe full
        instrumentation occurred when it did not.
        """
        print("[+] Loading default scripts...")

        for script_path, script_name in self.default_scripts:
            full_path = self.script_dir / script_path

            if full_path.exists():
                success = self.load_script(str(full_path), script_name)
                self.capabilities[script_name] = AVAILABLE if success else FAILED
                print(f"    {'✓' if success else '✗'} {script_name}"
                      f"{'' if success else ' (FAILED)'}")
            else:
                self._create_basic_script(script_path, script_name)

        degraded = [n for n, s in self.capabilities.items() if s == DEGRADED]
        failed = [n for n, s in self.capabilities.items() if s == FAILED]
        if degraded:
            print(f"[~] DEGRADED (generated substitute, partial coverage): {', '.join(degraded)}")
        if failed:
            print(f"[!] FAILED (no instrumentation): {', '.join(failed)}")

    def _create_basic_script(self, script_path: str, script_name: str):
        """Load a limited generated substitute for a missing script file."""
        script_content = self._get_basic_script_content(script_name)
        if script_content:
            success = self.load_script_content(script_content, script_name)
            self.capabilities[script_name] = DEGRADED if success else FAILED
            if success:
                print(f"    ~ {script_name} (DEGRADED - basic generated substitute)")
            else:
                print(f"    ✗ {script_name} (FAILED)")
        else:
            # No real file and no substitute available: this capability is absent.
            self.capabilities[script_name] = FAILED
            print(f"    ✗ {script_name} (FAILED - script file missing, no substitute)")
    
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
    
    # Explicit event type -> category. Scripts should set payload['type'];
    # content-sniffing is only a last resort.
    _TYPE_TO_CATEGORY = {
        'network': 'network_requests',
        'file': 'file_operations',
        'crypto': 'crypto_operations',
        'jwt': 'jwt_tokens',
        'token': 'jwt_tokens',
        'ssl': 'ssl_bypasses',
        'certificate': 'ssl_bypasses',
        'debug': 'anti_debug_bypasses',
        'bypass': 'anti_debug_bypasses',
        'api': 'api_calls',
    }

    def _categorize_data(self, payload: Any):
        """Categorize a collected event.

        Prefers the explicit ``type`` field the script sets; only falls back to
        content sniffing when it is absent. Each event gets a monotonic sequence
        number, and when a category reaches its cap the event is counted in
        ``dropped_events`` instead of being silently discarded (#12).
        """
        if not isinstance(payload, dict):
            return

        self._seq += 1
        payload.setdefault('seq', self._seq)

        data_type = str(payload.get('type', '')).lower()
        category = self._TYPE_TO_CATEGORY.get(data_type)

        if category is None:
            # Last-resort content sniffing (marked so reviewers know it is a guess).
            blob = str(payload).lower()
            if 'url' in payload or 'http' in blob:
                category = 'network_requests'
            elif 'path' in payload or 'file' in blob:
                category = 'file_operations'
            elif 'cipher' in blob or 'encrypt' in blob:
                category = 'crypto_operations'
            elif 'jwt' in blob or 'token' in blob:
                category = 'jwt_tokens'
            elif 'ssl' in blob or 'certificate' in blob:
                category = 'ssl_bypasses'
            elif 'debug' in blob or 'bypass' in blob:
                category = 'anti_debug_bypasses'
            else:
                category = 'api_calls'
            payload['_classified_by'] = 'content_sniff'

        if len(self.data_collected[category]) < self.config['max_data_per_category']:
            self.data_collected[category].append(payload)
        else:
            self.dropped_events[category] = self.dropped_events.get(category, 0) + 1
    
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
            'engagement': self.roe.identity() if self.roe else None,
            'analysis_start_time': getattr(self, 'start_time', time.time()),
            'analysis_end_time': time.time(),
            'scripts_loaded': len(self.scripts),
            'capabilities': self.capabilities,
            'dropped_events': self.dropped_events,
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
        """Save analysis reports. Runtime data is REDACTED unless reveal_raw.

        Collected runtime data can contain JWTs, tokens, and secrets. The full
        capture goes to the encrypted evidence store (if configured); the report
        files written to the output directory are redacted by default (#2).
        """
        # Full, unredacted capture -> encrypted evidence store.
        if self.evidence is not None:
            custody = self.evidence.store('frida_capture', report, reveal_raw=self.reveal_raw)
            report['evidence'] = custody
            if self.audit:
                self.audit.record('evidence_stored', custody)

        out_report = report if self.reveal_raw else redact(report, reveal=False)

        # Save JSON report (redacted by default)
        json_report_file = self.output_dir / 'frida_analysis_report.json'
        with open(json_report_file, 'w') as f:
            json.dump(out_report, f, indent=2, default=str)
        if not self.reveal_raw:
            print("[+] Runtime data in report is redacted; raw capture is in the "
                  "encrypted evidence store if --evidence-dir was set.")
        
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
        
        # Save network activity log (from the redacted view)
        if out_report['data_collected']['network_requests']:
            network_file = self.output_dir / 'network_activity.log'
            with open(network_file, 'w') as f:
                for req in out_report['data_collected']['network_requests']:
                    f.write(f"{req.get('timestamp', 'N/A')} - {req.get('url', 'N/A')}\n")

        # Save crypto operations log (from the redacted view)
        if out_report['data_collected']['crypto_operations']:
            crypto_file = self.output_dir / 'crypto_operations.log'
            with open(crypto_file, 'w') as f:
                for op in out_report['data_collected']['crypto_operations']:
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
    # Safety-layer options.
    parser.add_argument('--roe', help='Signed Rules-of-Engagement JSON (required unless --allow-no-roe)')
    parser.add_argument('--trusted-key', action='append', default=[],
                        help='Trusted authorizer public key (hex); repeatable')
    parser.add_argument('--allow-untrusted-roe', action='store_true',
                        help='LAB ONLY: accept a signed ROE whose key is not trusted')
    parser.add_argument('--allow-no-roe', action='store_true',
                        help='LAB ONLY: run without an ROE (no package-scope enforcement)')
    parser.add_argument('--evidence-dir', help='Directory for the encrypted evidence store')
    parser.add_argument('--evidence-passphrase', help='Passphrase (or set EVIDENCE_PASSPHRASE)')
    parser.add_argument('--reveal-raw', action='store_true',
                        help='Write raw runtime data into reports instead of redacting (audited)')
    parser.add_argument('--audit-log', help='Path to the tamper-evident audit log (JSONL)')

    args = parser.parse_args()

    try:
        # Build the safety layer. A signed, in-scope ROE is required unless the
        # operator explicitly opts into lab mode.
        roe = None
        if args.roe:
            roe = RulesOfEngagement.load(
                args.roe, trusted_keys=args.trusted_key or None,
                require_trusted=not args.allow_untrusted_roe,
            )
        elif not args.allow_no_roe:
            print("[-] A signed --roe is required (or --allow-no-roe for lab use). Refusing.")
            sys.exit(3)

        audit = AuditLog(args.audit_log, identity=(roe.identity() if roe else {"tool": "frida"})) \
            if args.audit_log else None
        evidence = EvidenceStore(args.evidence_dir, passphrase=args.evidence_passphrase) \
            if args.evidence_dir else None

        # Create automation instance
        automation = FridaAutomation(
            args.package_name, args.output,
            roe=roe, evidence=evidence, audit=audit, reveal_raw=args.reveal_raw,
        )
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
