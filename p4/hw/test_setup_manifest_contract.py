import os
import pathlib
import subprocess
import tempfile
import unittest


HW_DIR = pathlib.Path(__file__).resolve().parent
REPO_ROOT = HW_DIR.parents[1]


class SetupManifestScriptContractTest(unittest.TestCase):
    def test_deploy_dry_run_ships_and_seals_setup_scripts_separately(self):
        output = self._dry_run("deploy.sh", "mcp_fabric_gate_event")

        self.assertIn("setup_skeleton.py", output)
        self.assertIn("setup_attention.py", output)
        self.assertIn("setup-manifest.sha256", output)
        self.assertIn("seal setup scripts with SHA-256", output)

        build_section = output[output.index("seal compiler inputs and loadable outputs"):]
        build_section = build_section[:build_section.index("seal setup scripts with SHA-256")]
        self.assertNotIn("setup_skeleton.py", build_section)
        self.assertNotIn("setup_attention.py", build_section)

    def test_bringup_dry_run_verifies_setup_manifest_before_setup_scripts_run(self):
        output = self._dry_run("bringup.sh", "mcp_fabric_gate_event")

        verify_at = output.index("setup provenance: verify shipped setup scripts")
        skeleton_at = output.index("python3 setup_skeleton.py")
        attention_at = output.index("python3 setup_attention.py")
        self.assertLess(verify_at, skeleton_at)
        self.assertLess(verify_at, attention_at)
        self.assertNotIn("[dry-run] scp", output)
        self.assertIn("tbl_eg_vlink verified: 16 exact rows", output)

    def test_bringup_waits_for_cold_port_training_with_a_bounded_timeout(self):
        output = self._dry_run(
            "bringup.sh", "mcp_fabric_gate_event", "--port-timeout", "17"
        )

        self.assertIn("wait up to 17s for all loop pairs and host ports", output)
        self.assertIn("training poll every 2s", output)

    def test_deploy_dry_run_ships_and_seals_gate_runtime_separately(self):
        output = self._dry_run("deploy.sh", "mcp_fabric_gate_event")

        for name in ("gate_agent.py", "gate_agent_core.py", "injector_ranges.py"):
            self.assertIn(name, output)
        self.assertIn("runtime-manifest.sha256", output)
        self.assertIn("seal gate-agent runtime with SHA-256", output)

        build_section = output[output.index("seal compiler inputs and loadable outputs"):]
        build_section = build_section[:build_section.index("seal setup scripts with SHA-256")]
        setup_section = output[output.index("seal setup scripts with SHA-256"):]
        setup_section = setup_section[:setup_section.index("seal gate-agent runtime with SHA-256")]
        for name in ("gate_agent.py", "gate_agent_core.py", "injector_ranges.py"):
            self.assertNotIn(name, build_section)
            self.assertNotIn(name, setup_section)

    def test_runtime_only_deploy_skips_compiler_and_other_manifests(self):
        output = self._dry_run(
            "deploy.sh", "mcp_fabric_gate_event", "--runtime-only"
        )

        self.assertIn("runtime-only", output)
        self.assertIn("seal gate-agent runtime", output)
        self.assertNotIn("bf-p4c", output)
        self.assertNotIn("build-manifest.sha256", output)
        self.assertNotIn("setup-manifest.sha256", output)

    def test_gate_agent_requires_explicit_program_and_verifies_all_identities(self):
        source = (HW_DIR / "loop" / "gate_agent.py").read_text()
        self.assertIn('os.environ.get("MCP_PROG")', source)
        self.assertNotIn('os.environ.get("MCP_PROG",', source)
        self.assertIn("verify_sha256_manifest", source)
        self.assertIn("verify_loaded_build", source)
        self.assertIn('f[0] == "V"', source)

    def _dry_run(self, script, program, *extra):
        with tempfile.TemporaryDirectory() as tmp:
            for name in ("ssh", "scp"):
                path = pathlib.Path(tmp) / name
                path.write_text("#!/bin/sh\nprintf 'unexpected %s\\n' \"$0\" >&2\nexit 99\n")
                path.chmod(0o755)
            env = os.environ.copy()
            env["PATH"] = f"{tmp}{os.pathsep}{env['PATH']}"
            proc = subprocess.run(
                [str(HW_DIR / script), program, "--dry-run", *extra],
                cwd=REPO_ROOT,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertNotIn("unexpected", proc.stdout)
        return proc.stdout


if __name__ == "__main__":
    unittest.main()
