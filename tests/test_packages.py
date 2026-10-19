"""Debian versions, APT policy classification, holds, simulation parsing and
.deb identity checks."""

import os
import tempfile
import unittest

from helpers import DEBIAN_REPO, VENDOR_REPO, FakeSystem, make_deb, needs_dpkg

from wardctl import apt, debpkg
from wardctl.errors import VerificationError
from wardctl.runner import Runner

REAL_POLICY = """\
okular:
  Installed: 4:25.04.2-1+deb13u1
  Candidate: 4:25.04.2-1+deb13u1
  Version table:
 *** 4:25.04.2-1+deb13u1 500
        500 http://deb.debian.org/debian trixie/main amd64 Packages
        500 http://security.debian.org/debian-security trixie-security/main amd64 Packages
        100 /var/lib/dpkg/status
obsidian:
  Installed: 1.14.4
  Candidate: 1.14.4
  Version table:
 *** 1.14.4 100
        100 /var/lib/dpkg/status
claude-desktop:
  Installed: 2.42304.0
  Candidate: 2.42304.0
  Version table:
 *** 2.42304.0 500
        500 https://downloads.claude.ai/claude-desktop/apt/stable stable/main amd64 Packages
        100 /var/lib/dpkg/status
     2.37337.1 500
        500 https://downloads.claude.ai/claude-desktop/apt/stable stable/main amd64 Packages
"""

REAL_ORIGINS = """\
Package files:
 100 /var/lib/dpkg/status
     release a=now
 500 https://downloads.claude.ai/claude-desktop/apt/stable stable/main amd64 Packages
     release o=Anthropic,a=stable,n=stable,l=Anthropic,c=main,b=amd64
     origin downloads.claude.ai
 500 http://deb.debian.org/debian trixie/main amd64 Packages
     release v=13.7,o=Debian,a=stable,n=trixie,l=Debian,c=main,b=amd64
     origin deb.debian.org
Pinned packages:
"""


@needs_dpkg
class VersionTests(unittest.TestCase):
    def setUp(self):
        self.cmp = debpkg.VersionComparer(Runner())

    def test_epochs_revisions_and_tilde(self):
        cases = [("1:1.0", "2.0", 1), ("2.0-1", "2.0-2", -1), ("1.0~rc1", "1.0", -1),
                 ("4:25.04.2-1+deb13u1", "4:25.04.2-1", 1), ("1.0", "1.0", 0), ("1.0-0", "1.0", 0),
                 ("1.2.10", "1.2.9", 1), ("1:1.2.95.453.g0eeebbed", "1:1.2.95.453.g0eeebbed", 0)]
        for a, b, want in cases:
            with self.subTest(a=a, b=b):
                self.assertEqual(self.cmp.compare(a, b), want)

    def test_newest(self):
        self.assertEqual(self.cmp.newest(["1.9", "1:0.1", "1.10"]), "1:0.1")


class PolicyParsingTests(unittest.TestCase):
    def test_real_output(self):
        pols = apt.parse_policy(REAL_POLICY)
        self.assertEqual(set(pols), {"okular", "obsidian", "claude-desktop"})
        self.assertEqual(len(pols["okular"].repository_sources()), 2)
        self.assertEqual(pols["obsidian"].repository_versions(), [])
        self.assertEqual([v.version for v in pols["claude-desktop"].repository_versions()],
                         ["2.42304.0", "2.37337.1"])

    def test_origins(self):
        origins = apt.parse_origins(REAL_ORIGINS)
        self.assertEqual(origins["http://deb.debian.org/debian trixie/main amd64 Packages"], "Debian")
        self.assertEqual(origins["https://downloads.claude.ai/claude-desktop/apt/stable stable/main amd64 "
                                 "Packages"], "Anthropic")


@needs_dpkg
class ClassifyTests(unittest.TestCase):
    def setUp(self):
        self.sys = FakeSystem()
        self.cmp = debpkg.VersionComparer(Runner())

    def classify(self, name):
        pol = apt.parse_policy(self.sys.policy_block(name)).get(name)
        inst = self.sys.installed.get(name)
        return apt.classify(inst[0] if inst else None, pol, self.cmp)

    def test_dpkg_status_is_not_a_repository(self):
        self.sys.install("obsidian", "1.14.4")
        self.assertEqual(self.classify("obsidian"), (apt.INSTALLED_ONLY, None))

    def test_current_and_upgradable_with_epoch(self):
        self.sys.install("spotify-client", "1:1.2.95")
        self.sys.offer("spotify-client", "1:1.2.95", VENDOR_REPO)
        self.assertEqual(self.classify("spotify-client")[0], apt.CURRENT)
        self.sys.offer("spotify-client", "1:1.2.96", VENDOR_REPO)
        self.assertEqual(self.classify("spotify-client"), (apt.UPGRADABLE, "1:1.2.96"))

    def test_installed_newer_than_repository_is_not_an_update(self):
        self.sys.install("keepassxc", "2.8.0-1")
        self.sys.offer("keepassxc", "2.7.10+dfsg1-1", DEBIAN_REPO)
        status, repo_version = self.classify("keepassxc")
        self.assertEqual(status, apt.INSTALLED_NEWER)
        self.assertEqual(repo_version, "2.7.10+dfsg1-1")

    def test_not_installed(self):
        self.sys.offer("okular", "4:25.04.2-1")
        self.assertEqual(self.classify("okular")[0], apt.NOT_INSTALLED)
        self.assertEqual(apt.classify(None, None, self.cmp)[0], apt.UNAVAILABLE)


class SimulationTests(unittest.TestCase):
    def test_apt2_kept_back_and_upgrades(self):
        text = ("Reading package lists...\nThe following packages have been kept back:\n  linux-image-amd64 "
                "mesa\nThe following packages will be upgraded:\n  okular\n"
                "Inst okular [4:25.04.2-1] (4:25.04.2-1+deb13u1 Debian:13.7/stable [amd64])\n"
                "Conf okular (4:25.04.2-1+deb13u1 Debian:13.7/stable [amd64])\n")
        plan = apt.parse_simulation(text)
        self.assertEqual(plan.upgrades, [("okular", "4:25.04.2-1", "4:25.04.2-1+deb13u1")])
        self.assertEqual(plan.kept_back, ["linux-image-amd64", "mesa"])

    def test_apt3_not_upgrading(self):
        text = ("Upgrading:\n  okular\nNot upgrading:\n  libfoo1\n\nSummary:\n"
                "Inst okular [1] (2 Debian:13/stable [amd64])\nInst newdep (1 Debian:13/stable [amd64])\n"
                "Remv olddep [1]\n")
        plan = apt.parse_simulation(text)
        self.assertEqual(plan.kept_back, ["libfoo1"])
        self.assertEqual(plan.installs, [("newdep", "1")])
        self.assertEqual(plan.removals, ["olddep"])

    def test_lock_error_detection(self):
        self.assertTrue(apt.lock_error("E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by "
                                       "process 1234 (apt-get)"))
        self.assertFalse(apt.lock_error("E: Some index files failed to download"))


class AptCommandTests(unittest.TestCase):
    def test_default_is_upgrade_not_full_upgrade_and_no_unsafe_flags(self):
        a = apt.Apt(FakeSystem())
        argv = a.upgrade_argv()
        self.assertEqual(argv[-1], "upgrade")
        joined = " ".join(argv + a.refresh_argv() + a.install_argv(["/x.deb"]))
        for bad in ("--allow-unauthenticated", "full-upgrade", "dist-upgrade", "autoremove", "--force-yes",
                    "--allow-downgrades", "AllowInsecureRepositories"):
            self.assertNotIn(bad, joined)
        self.assertIn("--error-on=any", a.refresh_argv())

    def test_noninteractive_conffile_policy(self):
        a = apt.Apt(FakeSystem(), yes=True)
        argv = a.upgrade_argv()
        self.assertIn("-y", argv)
        self.assertIn("Dpkg::Options::=--force-confold", argv)
        self.assertIn("Dpkg::Options::=--force-confdef", argv)
        self.assertEqual(a._env()["DEBIAN_FRONTEND"], "noninteractive")
        self.assertIn("Dpkg::Options::=--force-confnew", apt.Apt(FakeSystem(), True, "use-new").upgrade_argv())
        self.assertNotIn("-y", apt.Apt(FakeSystem()).upgrade_argv())

    def test_held_packages_only_changed_with_explicit_flag(self):
        a = apt.Apt(FakeSystem())
        self.assertNotIn("--allow-change-held-packages", a.install_argv(["x"]))
        self.assertIn("--allow-change-held-packages", a.install_argv(["x"], allow_held=True))


@needs_dpkg
class DebInspectionTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.runner = Runner()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.dir, True)

    def write(self, name, data):
        path = os.path.join(self.dir, name)
        with open(path, "wb") as fh:
            fh.write(data)
        return path

    def test_reads_identity(self):
        make_deb(self.dir, "obsidian", "1:1.15.0-2", name="o.deb")
        info = debpkg.inspect_deb(self.runner, os.path.join(self.dir, "o.deb"))
        self.assertEqual((info.package, info.version, info.arch), ("obsidian", "1:1.15.0-2", "amd64"))

    def test_truncated_head_is_enough_for_control(self):
        data = make_deb(self.dir, "obsidian", "1.15.0", name="o.deb")
        path = self.write("head.deb", data[:4096])
        self.assertEqual(debpkg.inspect_deb(self.runner, path).version, "1.15.0")

    def test_html_masquerading_as_deb_rejected(self):
        path = self.write("fake.deb", b"<!DOCTYPE html><html><body>Download</body></html>")
        with self.assertRaises(VerificationError) as cm:
            debpkg.inspect_deb(self.runner, path)
        self.assertIn("HTML", str(cm.exception))

    def test_corrupt_ar_rejected(self):
        path = self.write("bad.deb", b"!<arch>\ndebian-binary   garbage")
        with self.assertRaises(VerificationError):
            debpkg.inspect_deb(self.runner, path)

    def test_identity_and_architecture_enforced(self):
        app = {"id": "obsidian", "packages": ["obsidian"], "architectures": ["amd64"]}
        debpkg.check_identity(debpkg.DebInfo("obsidian", "1.0", "amd64"), app, "amd64")
        debpkg.check_identity(debpkg.DebInfo("obsidian", "1.0", "all"), app, "amd64")
        with self.assertRaises(VerificationError) as cm:
            debpkg.check_identity(debpkg.DebInfo("evil", "1.0", "amd64"), app, "amd64")
        self.assertIn("wardctl set obsidian --package evil", cm.exception.hint)
        with self.assertRaises(VerificationError):
            debpkg.check_identity(debpkg.DebInfo("obsidian", "1.0", "arm64"), app, "amd64")
        app["identity"] = {"package": "obsidian-renamed", "architecture": "amd64"}
        with self.assertRaises(VerificationError):
            debpkg.check_identity(debpkg.DebInfo("obsidian", "1.0", "amd64"), app, "amd64")

    def test_query_installed_and_holds(self):
        fs = FakeSystem()
        fs.install("okular", "4:25.04.2-1")
        fs.install("qbittorrent", "5.1.0-2")
        fs.hold("qbittorrent")
        got = debpkg.query_installed(fs, ["okular", "qbittorrent", "missing"])
        self.assertEqual(set(got), {"okular", "qbittorrent"})
        self.assertTrue(got["qbittorrent"].held)
        self.assertFalse(got["okular"].held)


if __name__ == "__main__":
    unittest.main()
