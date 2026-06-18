"""
Dynamic Analysis Engine — runs the target APK on a connected device/emulator
using Frida to hook API calls and log runtime behaviors.

Frida 17+ Breaking Change:
  The Java bridge is no longer auto-bundled in agent scripts.
  We use frida.Compiler to compile agent.js (which has
  `import Java from 'frida-java-bridge'`) into a self-contained bundle
  before injecting it into the target process.
"""

import os
import time
from pathlib import Path
from typing import Optional, Callable


class DynamicAnalyzer:
    """
    Frida Dynamic Instrumentation Engine.
    Spawns target application on emulator/device, injects agent.js,
    and captures runtime API calls (crypto, SMS, network, etc.)
    """

    def __init__(self, agent_script_path: Optional[str] = None):
        self.agent_script_path = agent_script_path or str(
            Path(__file__).resolve().parent.parent.parent / "frida_scripts" / "agent.js"
        )
        self.device = None
        self.session = None
        self.script = None
        self.events = []
        self._compiled_source = None  # Cache the compiled bundle

    def is_frida_available(self) -> bool:
        """Check if frida package is installed."""
        try:
            import frida
            return True
        except ImportError:
            return False

    def _compile_agent(self) -> str:
        """
        Compile agent.js using frida.Compiler to resolve the
        `import Java from 'frida-java-bridge'` statement.
        Returns the bundled JavaScript source ready for create_script().
        """
        if self._compiled_source:
            return self._compiled_source

        import frida

        script_path = os.path.abspath(self.agent_script_path)
        project_root = str(Path(script_path).parent)

        print(f"[Dynamic] Compiling Frida agent from {script_path}...")
        try:
            compiler = frida.Compiler()
            self._compiled_source = compiler.build(
                script_path,
                project_root=project_root
            )
            print(f"[Dynamic] Agent compiled successfully ({len(self._compiled_source)} bytes)")
            return self._compiled_source
        except Exception as e:
            print(f"[Dynamic] frida.Compiler failed ({e}), falling back to raw script")
            # Fallback: read the raw script (will fail on Java import but worth trying)
            with open(script_path, "r", encoding="utf-8") as f:
                raw = f.read()
            # Strip the import line so at least we don't get a syntax error
            lines = raw.split('\n')
            filtered = [l for l in lines if not l.strip().startswith('import Java')]
            # Prepend a comment noting the bridge is missing
            fallback = "// WARNING: frida-java-bridge not bundled — Java hooks may not work\n"
            fallback += '\n'.join(filtered)
            return fallback

    def start_analysis(
        self,
        package_name: str,
        apk_path: Optional[str] = None,
        duration_seconds: int = 8,
        event_callback: Optional[Callable] = None
    ) -> list:
        """
        Spawn package_name, inject agent.js, and capture hooks.
        Gracefully handles missing devices/errors without crashing.
        """
        self.events = []
        if not self.is_frida_available():
            print("[Dynamic] Frida Python library not installed.")
            return [{
                "type": "error",
                "message": "Frida not installed on backend. Run: pip install frida frida-tools"
            }]

        import frida

        try:
            # ── Step 1: Connect to device ─────────────────────────
            try:
                self.device = frida.get_usb_device(timeout=5)
            except Exception:
                try:
                    self.device = frida.get_local_device()
                except Exception:
                    devices = frida.get_device_manager().enumerate_devices()
                    if devices:
                        self.device = devices[0]
                    else:
                        raise Exception("No Android emulator or USB device found.")

            print(f"[Dynamic] Connected to device: {self.device.name}")

            # ── Step 2: Install APK on device/emulator ────────────
            if apk_path and Path(apk_path).exists():
                import subprocess
                import shutil
                print(f"[Dynamic] Installing APK on device: {apk_path}")
                
                project_root = Path(__file__).resolve().parent.parent.parent
                local_adb = project_root / "android_sdk" / "platform-tools" / "adb"
                adb_cmd = str(local_adb) if local_adb.exists() else shutil.which("adb") or "adb"
                
                result = subprocess.run(
                    [adb_cmd, "install", "-r", "-t", "--bypass-low-target-sdk-block", str(apk_path)],
                    capture_output=True, text=True, timeout=60
                )
                if result.returncode == 0:
                    print("[Dynamic] APK installed successfully.")
                else:
                    print(f"[Dynamic] APK install warning: {result.stderr.strip()}")
                time.sleep(3)  # Let package manager register the app

            # ── Step 3: Compile the Frida agent ───────────────────
            script_code = self._compile_agent()

            # ── Step 4: Spawn, attach, inject, resume ─────────────
            pid = self.device.spawn([package_name])
            self.session = self.device.attach(pid)

            self.script = self.session.create_script(script_code)

            def on_message(message, data):
                if message['type'] == 'send':
                    payload = message['payload']
                    if event_callback:
                        event_callback(payload)
                    self.events.append(payload)
                elif message['type'] == 'error':
                    print(f"[Dynamic] Frida script error: {message}")
                    self.events.append({
                        "type": "error",
                        "message": message.get("description", "Frida execution error")
                    })

            self.script.on('message', on_message)
            self.script.load()

            # Resume process AFTER script is loaded
            self.device.resume(pid)
            print(f"[Dynamic] Spawned & resumed {package_name} (PID: {pid})")

            # Let it run for the specified duration to collect hooks
            time.sleep(duration_seconds)

            # Cleanup
            try:
                self.session.detach()
            except Exception:
                pass

            print("[Dynamic] Dynamic analysis finished.")
            return self.events

        except Exception as e:
            print(f"[Dynamic] Dynamic analysis failed: {e}")
            return [{
                "type": "warning",
                "message": f"No active device/emulator with Frida server running: {e}"
            }]
