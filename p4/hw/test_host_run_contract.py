import os
import pathlib
import subprocess
import tempfile
import textwrap
import unittest


HW_DIR = pathlib.Path(__file__).resolve().parent
REPO_ROOT = HW_DIR.parents[1]


class HostRunContractTest(unittest.TestCase):
    def _run(self, fetch_body: str, fetch_status: int = 0):
        with tempfile.TemporaryDirectory() as tmp:
            fake = pathlib.Path(tmp) / "sshpass"
            fake.write_text(
                textwrap.dedent(
                    f"""\
                    #!/bin/sh
                    case "$*" in
                      *"cat /tmp/host_run."*)
                        printf '%b' {fetch_body!r}
                        exit {fetch_status}
                        ;;
                    esac
                    exit 0
                    """
                )
            )
            fake.chmod(0o755)
            env = os.environ.copy()
            env["PATH"] = f"{tmp}{os.pathsep}{env['PATH']}"
            env.setdefault("SSHPASS", "test-only")
            env.setdefault("HOST_SUDO_PASS", "test-only")
            env.setdefault("HOST_SUDO_USER", "test-only")
            return subprocess.run(
                [str(HW_DIR / "host_run.sh"), "--user", "vision", "true"],
                cwd=REPO_ROOT,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )

    def test_propagates_exact_remote_status(self):
        proc = self._run("payload\n---RC---\n7\n")
        self.assertEqual(proc.returncode, 7, proc.stdout)
        self.assertEqual(proc.stdout, "payload\n")

    def test_missing_remote_status_fails_closed_with_diagnostic(self):
        proc = self._run("payload\n---RC---\n")
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertIn("missing or invalid remote exit status", proc.stdout)
        self.assertNotIn("numeric argument required", proc.stdout)

    def test_fetch_failure_fails_closed_with_diagnostic(self):
        proc = self._run("", fetch_status=255)
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertIn("could not fetch remote output", proc.stdout)


if __name__ == "__main__":
    unittest.main()
