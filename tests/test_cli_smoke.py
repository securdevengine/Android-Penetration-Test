import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = sorted((ROOT / "scripts").rglob("*.py"))


class CLISmokeTests(unittest.TestCase):
    def test_all_python_entry_points_support_help(self):
        self.assertEqual(len(SCRIPTS), 11)

        failures = []
        for script in SCRIPTS:
            result = subprocess.run(
                [sys.executable, str(script), "--help"],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=20,
            )
            output = result.stdout + result.stderr
            if result.returncode != 0 or "usage:" not in output.lower():
                failures.append(
                    f"{script.relative_to(ROOT)}: exit={result.returncode}\n{output}"
                )

        self.assertFalse(failures, "\n\n".join(failures))


if __name__ == "__main__":
    unittest.main()
