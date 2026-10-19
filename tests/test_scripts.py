"""install.sh / uninstall.sh ownership boundaries, run unprivileged against
a temporary prefix with a fake account database."""

import os
import shutil
import stat
import subprocess
import tempfile
import unittest

from helpers import ROOT

INSTALL = os.path.join(ROOT, "install.sh")
UNINSTALL = os.path.join(ROOT, "uninstall.sh")


@unittest.skipIf(os.geteuid() == 0, "script tests run unprivileged")
class ScriptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mrupd-scripts-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.prefix = os.path.join(self.tmp, "prefix")
        self.home = os.path.join(self.tmp, "home")
        os.makedirs(self.home)
        self.cache = os.path.join(self.tmp, "var-cache-wardctl")
        self.lock = os.path.join(self.tmp, "wardctl.lock")
        self.passwd = os.path.join(self.tmp, "passwd")
        with open(self.passwd, "w") as fh:
            fh.write(f"tester:x:{os.getuid()}:{os.getgid()}::{self.home}:/bin/sh\n")
        # Package-manager tripwires: any call is recorded.
        self.bin = os.path.join(self.tmp, "bin")
        os.makedirs(self.bin)
        self.trip = os.path.join(self.tmp, "tripwire")
        for tool in ("apt-get", "apt", "dpkg", "pip", "pip3", "flatpak"):
            path = os.path.join(self.bin, tool)
            with open(path, "w") as fh:
                fh.write(f"#!/bin/sh\necho {tool} \"$@\" >> {self.trip}\n")
            os.chmod(path, 0o755)

    def env(self, **extra):
        env = {"PATH": self.bin + ":/usr/bin:/bin", "HOME": "/nonexistent", "WARDCTL_TEST_MODE": "1",
               "WARDCTL_TEST_PASSWD": self.passwd, "WARDCTL_TEST_SYSTEM_CACHE": self.cache,
               "WARDCTL_TEST_SYSTEM_LOCK": self.lock}
        env.update(extra)
        return env

    def run_script(self, script, *args, cwd=None, **env):
        return subprocess.run([script, "--prefix", self.prefix, *args], cwd=cwd or "/", env=self.env(**env),
                              capture_output=True, text=True)

    def test_scripts_are_executable(self):
        for s in (INSTALL, UNINSTALL):
            self.assertTrue(os.stat(s).st_mode & stat.S_IXUSR, s)

    def test_install_from_any_directory_and_rerun(self):
        for _ in range(2):
            res = self.run_script(INSTALL, cwd=self.tmp)
            self.assertEqual(res.returncode, 0, res.stderr)
        launcher = os.path.join(self.prefix, "bin", "wardctl")
        self.assertTrue(os.access(launcher, os.X_OK))
        out = subprocess.run([launcher, "--version"], capture_output=True, text=True, env={"PATH": "/usr/bin"})
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("wardctl", out.stdout)
        lib = os.path.join(self.prefix, "lib", "wardctl")
        self.assertFalse([f for f in os.listdir(lib) if f.startswith(".stage")])
        self.assertTrue(os.path.exists(os.path.join(lib, "wardctl", "data", "keys", "veracrypt.gpg")))
        self.assertFalse(os.path.exists(self.trip), "installer must not call package managers")
        self.assertFalse(os.path.exists(os.path.join(self.home, ".wardctl")),
                         "installer must not create per-user state")

    def test_install_path_with_spaces(self):
        self.prefix = os.path.join(self.tmp, "pre fix")
        res = self.run_script(INSTALL)
        self.assertEqual(res.returncode, 0, res.stderr)
        out = subprocess.run([os.path.join(self.prefix, "bin", "wardctl"), "--version"],
                             capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)

    def test_install_refuses_foreign_launcher(self):
        os.makedirs(os.path.join(self.prefix, "bin"))
        with open(os.path.join(self.prefix, "bin", "wardctl"), "w") as fh:
            fh.write("#!/bin/sh\necho someone else\n")
        res = self.run_script(INSTALL)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("refusing to overwrite", res.stderr)

    def install_with_state(self):
        self.assertEqual(self.run_script(INSTALL).returncode, 0)
        cfg = os.path.join(self.home, ".wardctl")
        os.makedirs(cfg, 0o700)
        with open(os.path.join(cfg, "config.json"), "w") as fh:
            fh.write("{}")
        os.makedirs(os.path.join(self.cache, "staging"))
        with open(self.lock, "w"):
            pass
        # Unrelated files that must survive.
        other = os.path.join(self.prefix, "bin", "other-tool")
        with open(other, "w") as fh:
            fh.write("keep")
        shared = os.path.join(self.prefix, "lib", "shared-lib.so")
        with open(shared, "w") as fh:
            fh.write("keep")
        return cfg, other, shared

    def test_uninstall_removes_only_own_files_and_keeps_config(self):
        cfg, other, shared = self.install_with_state()
        res = self.run_script(UNINSTALL)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.prefix, "bin", "wardctl")))
        self.assertFalse(os.path.exists(os.path.join(self.prefix, "lib", "wardctl")))
        self.assertFalse(os.path.exists(self.cache))
        self.assertTrue(os.path.exists(other) and os.path.exists(shared))
        self.assertTrue(os.path.exists(os.path.join(cfg, "config.json")))
        self.assertIn("was kept", res.stdout)
        self.assertFalse(os.path.exists(self.trip), "uninstaller must not call package managers")

    def test_uninstall_ignores_tampered_manifest_entries(self):
        self.install_with_state()
        victim = os.path.join(self.tmp, "victim")
        with open(victim, "w") as fh:
            fh.write("keep")
        manifest = os.path.join(self.prefix, "lib", "wardctl", "MANIFEST")
        with open(manifest, "a") as fh:
            fh.write(f"{victim}\n{self.prefix}/lib/wardctl/../../../victim\n")
        res = self.run_script(UNINSTALL)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertTrue(os.path.exists(victim))

    def test_purge_config_removes_only_invoking_users_dir(self):
        cfg, _, _ = self.install_with_state()
        sibling = os.path.join(self.tmp, "home2", ".wardctl")
        os.makedirs(sibling)
        res = self.run_script(UNINSTALL, "--purge-config")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertFalse(os.path.exists(cfg))
        self.assertTrue(os.path.exists(sibling))
        self.assertTrue(os.path.isdir(self.home))

    def test_purge_refuses_symlinked_config(self):
        self.assertEqual(self.run_script(INSTALL).returncode, 0)
        target = os.path.join(self.tmp, "precious")
        os.makedirs(target)
        os.symlink(target, os.path.join(self.home, ".wardctl"))
        res = self.run_script(UNINSTALL, "--purge-config")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("symbolic link", res.stderr)
        self.assertTrue(os.path.isdir(target))

    def test_test_hook_ignored_without_test_mode(self):
        self.assertEqual(self.run_script(INSTALL).returncode, 0)
        env = self.env()
        del env["WARDCTL_TEST_MODE"]
        # Without the hook the real account database is used; purge would target the real home,
        # so only verify the program files are removed and no purge is requested.
        res = subprocess.run([UNINSTALL, "--prefix", self.prefix], env=env, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.prefix, "bin", "wardctl")))

    def test_scripts_contain_no_package_manager_calls(self):
        for script in (INSTALL, UNINSTALL):
            with open(script) as fh:
                body = "\n".join(line for line in fh if not line.lstrip().startswith("#"))
            for word in ("apt-get ", "apt ", "dpkg ", "pip ", "pip3 ", "flatpak "):
                self.assertNotIn(word, body.replace("sudo apt-get install python3", ""), (script, word))


if __name__ == "__main__":
    unittest.main()
