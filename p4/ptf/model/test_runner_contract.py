import pathlib
import subprocess
import tempfile
import textwrap
import unittest


RUNNER = pathlib.Path(__file__).with_name("run_context_regressions.sh")
RUNNER_LIB = pathlib.Path(__file__).with_name("runner_lib.sh")


class ContextRegressionRunnerContractTest(unittest.TestCase):
    def test_runner_never_uses_global_process_kills(self):
        text = RUNNER.read_text()
        self.assertNotIn("pkill", text)
        self.assertIn("refusing to kill pid", text)
        self.assertIn("PIDFILE", text)

    def test_runner_builds_current_sources_into_temporary_configs(self):
        text = RUNNER.read_text()
        self.assertIn("bf-p4c", text)
        self.assertIn("mktemp -d", text)
        self.assertIn("p4/witness/${prog}.p4", text)
        self.assertNotIn("model_capsule.conf", text)
        self.assertNotIn("model_gate.conf", text)

    def test_readiness_rejects_bfrt_grpc_bind_failure_even_if_status_port_listens(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            proc_root = root / "proc"
            proc_root.mkdir()
            switchd_pid = "1234"
            model_pid = "5678"
            (proc_root / switchd_pid).mkdir()
            (proc_root / model_pid).mkdir()
            switchd_pidfile = root / "bf_switchd.pid"
            model_pidfile = root / "tofino-model.pid"
            switchd_pidfile.write_text(switchd_pid)
            model_pidfile.write_text(model_pid)
            switchd_log = root / "switchd.log"
            model_log = root / "model.log"
            switchd_log.write_text(
                "\n".join(
                    [
                        "bf_switchd: server started - listening on port 9999",
                        "UNKNOWN:No address added out of total 1 resolved for '0.0.0.0:50052'",
                        "Address already in use",
                        "BF-RT Server Failed to start Server on 0.0.0.0:50052",
                        "ERROR: Failed to start bfrt grpc server: Resource temporarily not available",
                    ]
                )
            )
            model_log.write_text("")
            fake_bin = root / "bin"
            fake_bin.mkdir()
            fake_ss = fake_bin / "ss"
            fake_ss.write_text("#!/bin/sh\nprintf '%s\\n' 'LISTEN 0 4096 0.0.0.0:7777 0.0.0.0:*'\n")
            fake_ss.chmod(0o755)

            script = textwrap.dedent(
                f"""
                set -euo pipefail
                . {RUNNER_LIB}
                MODEL_RUNNER_PROC_ROOT={proc_root}
                PATH={fake_bin}:$PATH
                runner_bfrt_probe_ready() {{ return 0; }}
                if runner_wait_ready {switchd_pidfile} {model_pidfile} {switchd_log} {model_log} 7777 mcp_fabric_capsule 1; then
                    echo unexpected-ready
                    exit 1
                fi
                """
            )

            proc = subprocess.run(
                ["bash", "-c", script],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )

        self.assertNotEqual(proc.returncode, 1, proc.stdout)
        self.assertIn("fatal bf_switchd readiness log", proc.stdout)

    def test_readiness_rejects_status_port_without_bfrt_probe(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            proc_root = root / "proc"
            proc_root.mkdir()
            switchd_pid = "1234"
            model_pid = "5678"
            (proc_root / switchd_pid).mkdir()
            (proc_root / model_pid).mkdir()
            switchd_pidfile = root / "bf_switchd.pid"
            model_pidfile = root / "tofino-model.pid"
            switchd_pidfile.write_text(switchd_pid)
            model_pidfile.write_text(model_pid)
            switchd_log = root / "switchd.log"
            model_log = root / "model.log"
            switchd_log.write_text("bf_switchd: server started - listening on port 9999\n")
            model_log.write_text("")
            fake_bin = root / "bin"
            fake_bin.mkdir()
            fake_ss = fake_bin / "ss"
            fake_ss.write_text("#!/bin/sh\nprintf '%s\\n' 'LISTEN 0 4096 0.0.0.0:7777 0.0.0.0:*'\n")
            fake_ss.chmod(0o755)

            script = textwrap.dedent(
                f"""
                set -euo pipefail
                . {RUNNER_LIB}
                MODEL_RUNNER_PROC_ROOT={proc_root}
                PATH={fake_bin}:$PATH
                runner_bfrt_probe_ready() {{ return 1; }}
                if runner_wait_ready {switchd_pidfile} {model_pidfile} {switchd_log} {model_log} 7777 mcp_fabric_capsule 1; then
                    echo unexpected-ready
                    exit 1
                fi
                """
            )

            proc = subprocess.run(
                ["bash", "-c", script],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )

        self.assertNotEqual(proc.returncode, 1, proc.stdout)
        self.assertIn("timed out waiting for bf_switchd readiness", proc.stdout)

    def test_readiness_accepts_bfrt_probe_without_ready_log_line(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            proc_root = root / "proc"
            proc_root.mkdir()
            switchd_pid = "1234"
            model_pid = "5678"
            (proc_root / switchd_pid).mkdir()
            (proc_root / model_pid).mkdir()
            switchd_pidfile = root / "bf_switchd.pid"
            model_pidfile = root / "tofino-model.pid"
            switchd_pidfile.write_text(switchd_pid)
            model_pidfile.write_text(model_pid)
            switchd_log = root / "switchd.log"
            model_log = root / "model.log"
            switchd_log.write_text("bf_switchd: server started - listening on port 9999\n")
            model_log.write_text("")
            fake_bin = root / "bin"
            fake_bin.mkdir()
            fake_ss = fake_bin / "ss"
            fake_ss.write_text("#!/bin/sh\nprintf '%s\\n' 'LISTEN 0 4096 0.0.0.0:7777 0.0.0.0:*'\n")
            fake_ss.chmod(0o755)

            script = textwrap.dedent(
                f"""
                set -euo pipefail
                . {RUNNER_LIB}
                MODEL_RUNNER_PROC_ROOT={proc_root}
                PATH={fake_bin}:$PATH
                runner_bfrt_probe_ready() {{
                    [ "$1" = mcp_fabric_capsule ] && [ "$2" = 50052 ]
                }}
                runner_wait_ready {switchd_pidfile} {model_pidfile} {switchd_log} {model_log} 7777 mcp_fabric_capsule 1
                """
            )

            proc = subprocess.run(
                ["bash", "-c", script],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )

        self.assertEqual(proc.returncode, 0, proc.stdout)

    def test_model_lock_rejects_concurrent_runner(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            lock_path = root / "model.lock"
            holder = textwrap.dedent(
                f"""
                set -euo pipefail
                . {RUNNER_LIB}
                MODEL_RUNNER_LOCK_PATH={lock_path}
                runner_acquire_local_model_lock
                printf '%s\\n' ready
                sleep 3
                """
            )
            contender = textwrap.dedent(
                f"""
                set -euo pipefail
                . {RUNNER_LIB}
                MODEL_RUNNER_LOCK_PATH={lock_path}
                runner_acquire_local_model_lock
                """
            )
            first = subprocess.Popen(
                ["bash", "-c", holder],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            try:
                self.assertEqual(first.stdout.readline().strip(), "ready")
                second = subprocess.run(
                    ["bash", "-c", contender],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    check=False,
                )
            finally:
                first.terminate()
                first.wait(timeout=5)
                first.stdout.close()

        self.assertNotEqual(second.returncode, 0, second.stdout)
        self.assertIn("another local Tofino model runner holds", second.stdout)


if __name__ == "__main__":
    unittest.main()
