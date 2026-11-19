"""Which targets a run scans (1.5.0): a source flag never reaches the current kube context or this host's sshd
unless --cluster / --local-ssh ask for it. Offline: fake `oc` and `sudo` on PATH record every call."""
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PIPE = os.path.join(ROOT, "scripts", "tier2_pipeline.py")

FAKE = """#!/bin/sh
echo "$(basename "$0") $*" >> "{log}"
case "$*" in
  "config current-context") echo fake-ctx ;;
esac
exit 0
"""


class ModeSelection(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.log = os.path.join(d, "calls.log")
        self.bin = os.path.join(d, "bin")
        os.mkdir(self.bin)
        for name in ("oc", "kubectl", "sudo"):
            p = os.path.join(self.bin, name)
            with open(p, "w") as f:
                f.write(FAKE.format(log=self.log))
            os.chmod(p, 0o755)

    def tearDown(self):
        self.tmp.cleanup()

    def run_pipe(self, *args):
        env = dict(os.environ, PATH=self.bin + os.pathsep + os.environ.get("PATH", ""), KUBECONFIG="/dev/null")
        p = subprocess.run([sys.executable, "-I", PIPE, "--out", os.path.join(self.tmp.name, "out", "cbom.json"),
                            "--no-enumerate", "--no-classical-probe", *args],
                           capture_output=True, text=True, timeout=180, env=env)
        calls = ""
        if os.path.exists(self.log):
            with open(self.log) as f:
                calls = f.read()
        return p.returncode, p.stderr, calls

    def test_endpoints_alone_touch_no_cluster_and_no_sshd(self):
        rc, err, calls = self.run_pipe("--endpoints", "127.0.0.1:1")
        self.assertEqual(rc, 2, err[-300:])          # unreachable: nothing to assess (1.5.0)
        self.assertIn("none of the 1 endpoint(s)", err)
        self.assertNotIn("oc ", calls)
        self.assertNotIn("kubectl ", calls)
        self.assertNotIn("sshd", calls)

    def test_cluster_flag_scans_the_cluster(self):
        rc, err, calls = self.run_pipe("--cluster", "--endpoints", "127.0.0.1:1")
        self.assertIn("oc api-resources", calls)
        self.assertNotIn("sshd", calls)               # --local-ssh not given

    def test_local_ssh_flag_reads_sshd(self):
        rc, err, calls = self.run_pipe("--local-ssh", "--endpoints", "127.0.0.1:1")
        self.assertIn("sudo -n sshd -T", calls)
        self.assertNotIn("oc ", calls)

    def test_no_source_keeps_old_behaviour_and_names_the_context(self):
        rc, err, calls = self.run_pipe()
        self.assertIn("kube context 'fake-ctx'", err)
        self.assertIn("oc api-resources", calls)
        self.assertIn("sudo -n sshd -T", calls)

    def test_cluster_only_flags_need_cluster(self):
        for extra in (["--deep"], ["--kube-cli", "kubectl"], ["--debug-image", "x@sha256:" + "0" * 64]):
            rc, err, calls = self.run_pipe("--endpoints", "example.com", *extra)
            self.assertEqual(rc, 2, (extra, err[-300:]))
            self.assertIn("add --cluster", err)
            self.assertEqual(calls, "", extra)

    def test_cluster_and_no_runtime_conflict(self):
        rc, err, _ = self.run_pipe("--cluster", "--no-runtime", "--endpoints", "example.com")
        self.assertEqual(rc, 2)
        self.assertIn("contradict", err)


if __name__ == "__main__":
    unittest.main()
