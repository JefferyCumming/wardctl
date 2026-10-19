"""End-to-end behaviour through the CLI against a simulated dpkg/APT system,
fixture HTTP and a temporary home. Nothing touches the real machine."""

import hashlib
import io
import json
import os
import socket
import sys
import unittest
from unittest import mock

from helpers import (DEBIAN13, DEBIAN_REPO, VENDOR_REPO, FakeSystem, FakeTransport, TempHomeCase, fake_pw,
                     make_deb, needs_dpkg)

from wardctl import catalog, cli, privilege, resolvers, worker
from wardctl import runner as R
from wardctl.errors import EXIT_BUSY, EXIT_CONFIG, EXIT_FATAL, EXIT_OK, EXIT_PARTIAL, EXIT_UPDATES
from wardctl.netfetch import HttpClient

OBS_API = resolvers.GitHubReleaseResolver.API.format(repo="obsidianmd/obsidian-releases")
OBS_DL = "https://github.com/obsidianmd/obsidian-releases/releases/download/{tag}/obsidian_{v}_amd64.deb"
OBS_CDN = "https://release-assets.githubusercontent.com/obsidian-{v}?sig=TOKEN"
CHATGPT = "https://persistent.oaistatic.com/codex-app-prod/linux/deb/latest/chatgpt_amd64.deb"


@needs_dpkg
class Harness(TempHomeCase):
    def setUp(self):
        super().setUp()
        self.sys = FakeSystem()
        self.net = FakeTransport()
        self.http = HttpClient(self.net, sleep=lambda s: None)
        self.cache = os.path.join(self.tmp, "var-cache")
        self.debs = os.path.join(self.tmp, "debs")
        os.mkdir(self.debs)
        self.worker_calls = []
        for target, value in (("wardctl.catalog.probe_exists", False),
                              ("wardctl.debpkg.glob.glob", ["/usr/share/applications/fake.desktop"])):
            patcher = mock.patch(target, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)

    # -- environment
    def deps(self, euid=0, env=None, sudo=False):
        d = cli.Deps()
        d.runner = self.sys
        d.http = self.http
        d.euid = euid
        uid = os.getuid()
        d.env = env if env is not None else ({"SUDO_UID": str(uid)} if sudo else {})
        d.getpwuid = lambda u: fake_pw(self.home, uid=uid)
        d.stdout, d.stderr = io.StringIO(), io.StringIO()
        d.interactive = False
        d.platform = DEBIAN13
        d.system_cache = self.cache
        d.system_lock = os.path.join(self.tmp, "wardctl.lock")
        d.apt_lock_probe = lambda: None
        d.execv = mock.Mock()
        return d

    def run_cli(self, *argv, **kw):
        d = self.deps(**kw)
        code = cli.main(list(argv), d)
        self.out, self.err = d.stdout.getvalue(), d.stderr.getvalue()
        self.last_deps = d
        return code

    @property
    def cfg_path(self):
        return os.path.join(self.home, ".wardctl", "config.json")

    def cfg(self):
        with open(self.cfg_path) as fh:
            return json.load(fh)

    def state(self):
        with open(os.path.join(self.home, ".wardctl", "state.json")) as fh:
            return json.load(fh)

    # -- fixtures
    def base_system(self):
        s = self.sys
        s.install("okular", "4:25.04.2-1", maintainer="Debian Qt/KDE <debian-qt-kde@lists.debian.org>")
        s.offer("okular", "4:25.04.2-1", DEBIAN_REPO)
        s.install("obsidian", "1.14.4", homepage="https://obsidian.md")
        s.install("spotify-client", "1:1.2.95", maintainer="Spotify <tux@spotify.com>")
        s.offer("spotify-client", "1:1.2.95", VENDOR_REPO)
        s.install("foo-app", "3.0", homepage="https://foo.example")
        s.install("libfoo1", "1.0")
        s.install("coreutils", "9.7-3", maintainer="Debian <x@debian.org>")
        s.offer("coreutils", "9.7-3", DEBIAN_REPO)
        s.desktop |= {"okular", "obsidian", "spotify-client", "foo-app"}
        s.flatpaks[("com.discordapp.Discord", "user")] = "1.0.161"

    def obsidian_release(self, version, package="obsidian", arch="amd64"):
        tag = f"v{version}"
        name = f"obsidian_{version}_amd64.deb"
        data = make_deb(self.debs, package, version, arch=arch, name=name)
        self.net.add(OBS_API, json.dumps([{"tag_name": tag, "draft": False, "prerelease": False, "assets": [
            {"name": name, "browser_download_url": OBS_DL.format(tag=tag, v=version),
             "digest": "sha256:" + hashlib.sha256(data).hexdigest()}]}]).encode())
        self.net.redirect(OBS_DL.format(tag=tag, v=version), OBS_CDN.format(v=version))
        self.net.add(OBS_CDN.format(v=version), data)
        return data

    def proton_manifest(self, version, installed=True):
        if installed:
            self.sys.install("proton-pass", "1.42.0")
        data = make_deb(self.debs, "proton-pass", version, name=f"pp_{version}.deb")
        url = f"https://proton.me/download/pass/linux/proton-pass_{version}_amd64.deb"
        self.net.add("https://proton.me/download/PassDesktop/linux/x64/version.json", json.dumps({"Releases": [
            {"CategoryName": "Stable", "Version": version, "RolloutPercentage": 1,
             "File": [{"Url": url, "Sha512CheckSum": hashlib.sha512(data).hexdigest()}]}]}).encode())
        self.net.add(url, data)

    def init(self):
        self.assertEqual(self.run_cli("init", euid=os.getuid()), EXIT_OK, self.err)

    def downloads(self):
        return [u for u, h in self.net.requests if "Range" not in h and not u.endswith(".json")
                and "api.github.com" not in u]


class DiscoveryTests(Harness):
    def test_first_run_discovery_is_read_only_and_tracks_known_apps(self):
        self.base_system()
        self.init()
        apps = self.cfg()["apps"]
        self.assertEqual(set(apps), {"okular", "obsidian", "spotify", "discord"})
        self.assertEqual(apps["discord"]["flatpak"], {"app_id": "com.discordapp.Discord", "installation": "user"})
        self.assertEqual(apps["obsidian"]["provenance"]["install_origin"], "unknown")
        self.assertEqual(apps["obsidian"]["provenance"]["homepage_hint"], "https://obsidian.md")
        cands = self.state()["discovery"]["candidates"]
        self.assertEqual([c["package"] for c in cands], ["foo-app"])
        self.assertEqual(cands[0]["apt"], "installed-only")
        self.assertIn("unknown", cands[0]["provenance"])
        self.assertIn("Provenance of these packages is unknown", self.out)
        self.assertEqual(self.sys.mutations(), [])
        self.assertEqual(self.net.requests, [])  # discovery needs no network
        self.assertEqual(oct(os.stat(self.cfg_path).st_mode & 0o777), "0o600")

    def test_rediscovery_does_not_overwrite_user_changes(self):
        self.base_system()
        self.init()
        self.assertEqual(self.run_cli("set", "obsidian", "--policy", "check-only", euid=os.getuid()), 0)
        self.sys.install("veracrypt", "1.26.29-1~deb13-1")
        self.assertEqual(self.run_cli("discover", euid=os.getuid()), 0)
        apps = self.cfg()["apps"]
        self.assertEqual(apps["obsidian"]["update_policy"], "check-only")
        self.assertIn("veracrypt", apps)

    def test_repository_vs_installed_only_and_switch_to_apt(self):
        self.base_system()
        self.sys.install("chatgpt", "26.1013.40934")
        self.init()
        self.run_cli("status", "--json", euid=os.getuid())
        st = {s["app_id"]: s for s in json.loads(self.out)}
        self.assertEqual(st["okular"]["manager"], "apt")
        self.assertEqual(st["obsidian"]["manager"], "direct")
        self.assertEqual(st["chatgpt"]["manager"], "direct")
        # The .deb's installer adds the vendor repository: next evaluation prefers APT.
        self.sys.offer("chatgpt", "26.1013.40934", "https://persistent.oaistatic.com/codex-app-prod/linux/deb "
                                                    "stable/main amd64 Packages")
        self.run_cli("status", "--json", euid=os.getuid())
        st = {s["app_id"]: s for s in json.loads(self.out)}
        self.assertEqual(st["chatgpt"]["manager"], "apt")
        self.assertEqual(st["chatgpt"]["state"], "up-to-date")

    def test_unknown_source_is_reported_not_invented(self):
        self.sys.install("foo-app", "3.0")
        self.init()
        self.assertEqual(self.run_cli("add", "--package", "foo-app", euid=os.getuid()), 0)
        self.run_cli("check", "foo-app", euid=os.getuid())
        self.assertIn("unresolved source", self.out)
        self.assertIn("Where it was originally downloaded from is unknown", self.out)
        self.assertEqual(self.net.requests, [])

    def test_malformed_config_is_repairable_error(self):
        self.base_system()
        self.init()
        with open(self.cfg_path, "w") as fh:
            fh.write("{broken")
        self.assertEqual(self.run_cli("status", euid=os.getuid()), EXIT_CONFIG)
        self.assertIn("not valid JSON", self.err)
        self.assertEqual(self.run_cli("update", "--yes"), EXIT_CONFIG)
        with open(self.cfg_path) as fh:
            self.assertEqual(fh.read(), "{broken")


class CheckTests(Harness):
    def test_check_reports_updates_and_never_installs(self):
        self.base_system()
        self.init()
        self.obsidian_release("1.15.0")
        self.sys.flatpak_updates["user"].add("com.discordapp.Discord")
        self.assertEqual(self.run_cli("check", "--json", euid=os.getuid()), EXIT_UPDATES)
        res = {a["app_id"]: a for a in json.loads(self.out)["apps"]}
        self.assertEqual((res["obsidian"]["state"], res["obsidian"]["available"]), ("update-available", "1.15.0"))
        self.assertEqual(res["discord"]["state"], "update-available")
        self.assertEqual(res["okular"]["state"], "up-to-date")
        self.assertEqual(self.sys.mutations(), [])
        self.assertEqual(self.downloads(), [])  # only metadata + a ranged header read
        self.assertIn("last_check", self.state())

    def test_equal_and_newer_installed_are_not_updates(self):
        self.base_system()
        self.init()
        self.obsidian_release("1.14.4")
        self.sys.install("keepassxc", "2.8.0-1")
        self.sys.offer("keepassxc", "2.7.10+dfsg1-1", DEBIAN_REPO)
        self.run_cli("discover", euid=os.getuid())
        self.assertEqual(self.run_cli("check", "--json", euid=os.getuid()), EXIT_OK)
        res = {a["app_id"]: a for a in json.loads(self.out)["apps"]}
        self.assertEqual(res["obsidian"]["state"], "up-to-date")
        self.assertEqual(res["keepassxc"]["state"], "installed-newer")

    def test_network_error_is_partial_failure(self):
        self.base_system()
        self.init()
        self.net.error(OBS_API, socket.timeout("timed out"))
        self.assertEqual(self.run_cli("check", euid=os.getuid()), EXIT_PARTIAL)
        self.assertIn("network error", self.out)

    def test_system_upgrades_count_as_available(self):
        self.base_system()
        self.init()
        self.obsidian_release("1.14.4")
        self.sys.offer("coreutils", "9.7-4", DEBIAN_REPO)
        self.assertEqual(self.run_cli("check", euid=os.getuid()), EXIT_UPDATES)
        self.assertIn("1 package(s) upgradable", self.out)


class UpdateTests(Harness):
    def setUp(self):
        super().setUp()
        self.base_system()
        self.init()

    def test_full_update_flow(self):
        self.sys.offer("okular", "4:25.04.2-1+deb13u1", DEBIAN_REPO)
        self.obsidian_release("1.15.0")
        code = self.run_cli("update", "--yes")
        self.assertEqual(code, EXIT_OK, self.out + self.err)
        muts = self.sys.mutations()
        self.assertEqual(muts[0], [R.APT_GET, "update", "--error-on=any"])
        self.assertEqual(muts[1][-1], "upgrade")
        install = muts[2]
        self.assertIn("install", install)
        deb = install[-1]
        self.assertTrue(deb.startswith(os.path.join(self.cache, "staging")), deb)
        self.assertEqual(self.sys.installed["okular"][0], "4:25.04.2-1+deb13u1")
        self.assertEqual(self.sys.installed["obsidian"][0], "1.15.0")
        self.assertEqual(self.cfg()["apps"]["obsidian"]["identity"]["package"], "obsidian")
        self.assertEqual(os.listdir(os.path.join(self.cache, "staging")), [])           # root staging cleaned
        self.assertEqual(os.listdir(os.path.join(self.home, ".wardctl/cache/staging")), [])
        self.assertIn("completed successfully", self.out)
        self.assertEqual(self.state()["last_update"]["exit"], 0)

    def test_refresh_failure_stops_everything(self):
        self.sys.fail["refresh"] = 100
        self.obsidian_release("1.15.0")
        self.assertEqual(self.run_cli("update", "--yes"), EXIT_FATAL)
        self.assertEqual(len(self.sys.mutations()), 1)
        self.assertEqual(self.downloads(), [])
        self.assertIn("refresh failed", self.err)

    def test_upgrade_failure_does_not_fall_back_to_downloads(self):
        self.sys.offer("okular", "4:25.04.2-1+deb13u1", DEBIAN_REPO)
        self.sys.fail["upgrade"] = 100
        self.obsidian_release("1.15.0")
        self.assertEqual(self.run_cli("update", "--yes"), EXIT_PARTIAL)
        self.assertEqual(self.downloads(), [])
        self.assertEqual([m for m in self.sys.mutations() if "install" in m], [])
        self.assertIn("APT failed earlier", self.out)

    def test_partial_failure_summary(self):
        self.obsidian_release("1.15.0")
        self.proton_manifest("1.43.0")
        self.net.error("https://proton.me/download/PassDesktop/linux/x64/version.json", ConnectionResetError())
        self.run_cli("add", "proton-pass", euid=os.getuid())
        self.assertEqual(self.run_cli("update", "--yes", "--apps-only"), EXIT_PARTIAL)
        self.assertEqual(self.sys.installed["obsidian"][0], "1.15.0")
        self.assertEqual(self.sys.installed["proton-pass"][0], "1.42.0")
        self.assertRegex(self.out, r"proton-pass\s+failed")
        self.assertRegex(self.out, r"obsidian\s+ok")
        self.assertIn("completed with failures (exit 20)", self.out)

    def test_apt_lock_contention(self):
        d = self.deps()
        d.apt_lock_probe = lambda: ("/var/lib/dpkg/lock-frontend", 4242)
        self.assertEqual(cli.main(["update", "--yes"], d), EXIT_BUSY)
        self.assertIn("PID 4242", d.stderr.getvalue())
        self.assertEqual(self.sys.mutations(), [])

    def test_wardctl_lock_contention(self):
        from wardctl import config
        from helpers import make_identity
        with config.Store(make_identity(self.home)).user_lock():
            self.assertEqual(self.run_cli("update", "--yes"), EXIT_BUSY)
        self.assertEqual(self.sys.mutations(), [])

    def test_noninteractive_requires_yes(self):
        self.assertEqual(self.run_cli("update"), EXIT_FATAL)
        self.assertIn("--yes", self.err)
        self.assertEqual(self.sys.mutations(), [])

    def test_dry_run_changes_nothing(self):
        self.sys.offer("okular", "4:25.04.2-1+deb13u1", DEBIAN_REPO)
        self.obsidian_release("1.15.0")
        before = {p: open(os.path.join(self.home, ".wardctl", p), "rb").read()
                  for p in ("config.json", "state.json")}
        listing = sorted(os.listdir(os.path.join(self.home, ".wardctl")))
        code = self.run_cli("update", "--dry-run", euid=os.getuid())   # no root needed
        self.assertEqual(code, EXIT_OK, self.err)
        self.assertEqual(self.sys.mutations(), [])
        self.last_deps.execv.assert_not_called()
        self.assertEqual(self.downloads(), [])
        for p, data in before.items():
            self.assertEqual(open(os.path.join(self.home, ".wardctl", p), "rb").read(), data)
        self.assertEqual(sorted(os.listdir(os.path.join(self.home, ".wardctl"))), listing)
        self.assertFalse(os.path.exists(self.cache))
        self.assertIn("DRY RUN", self.out)
        self.assertIn("would download https://github.com/obsidianmd", self.out)
        self.assertIn("would run: /usr/bin/apt-get update --error-on=any", self.out)

    def test_held_direct_package_is_respected_unless_overridden(self):
        self.obsidian_release("1.15.0")
        self.sys.hold("obsidian")
        self.assertEqual(self.run_cli("update", "--yes", "--apps-only"), EXIT_OK)
        self.assertEqual(self.sys.installed["obsidian"][0], "1.14.4")
        self.assertRegex(self.out, r"obsidian\s+skipped\s+held")
        self.assertEqual(self.run_cli("set", "obsidian", "--allow-held-update", "yes", euid=os.getuid()), 0)
        self.assertEqual(self.run_cli("update", "--yes", "--apps-only"), EXIT_OK, self.out)
        install = [m for m in self.sys.mutations() if "install" in m][-1]
        self.assertIn("--allow-change-held-packages", install)

    def test_named_update_only_touches_that_app(self):
        self.sys.offer("okular", "4:25.04.2-1+deb13u1", DEBIAN_REPO)
        self.sys.offer("coreutils", "9.7-4", DEBIAN_REPO)
        self.assertEqual(self.run_cli("update", "okular", "--yes"), EXIT_OK, self.out)
        muts = self.sys.mutations()
        self.assertEqual(len(muts), 2)
        self.assertEqual(muts[1][-4:], ["install", "--only-upgrade", "--", "okular"])
        self.assertEqual(self.sys.installed["coreutils"][0], "9.7-3")

    def test_kept_back_reported_not_forced(self):
        self.sys.offer("spotify-client", "1:1.2.96", VENDOR_REPO)
        self.sys.sim_text = "The following packages have been kept back:\n  spotify-client\n"
        self.obsidian_release("1.14.4")
        self.assertEqual(self.run_cli("update", "--yes"), EXIT_OK)
        self.assertIn("kept back (not forced): spotify-client", self.out)
        self.assertRegex(self.out, r"spotify\s+skipped\s+kept back")

    def test_wrong_identity_from_established_source_not_installed(self):
        self.obsidian_release("1.15.0", package="obsidian-evil")
        self.assertEqual(self.run_cli("update", "--yes", "--apps-only"), EXIT_PARTIAL)
        self.assertEqual([m for m in self.sys.mutations() if "install" in m], [])
        self.assertIn("registered as 'obsidian'", self.out)

    def test_wrong_architecture_not_installed(self):
        self.obsidian_release("1.15.0", arch="arm64")
        self.assertEqual(self.run_cli("update", "--yes", "--apps-only"), EXIT_PARTIAL)
        self.assertEqual([m for m in self.sys.mutations() if "install" in m], [])

    def test_apt_install_failure_reported(self):
        self.obsidian_release("1.15.0")
        self.sys.fail["install"] = 100
        self.assertEqual(self.run_cli("update", "--yes", "--apps-only"), EXIT_PARTIAL)
        self.assertRegex(self.out, r"obsidian\s+failed\s+apt-get install exited 100")

    def test_tampered_staged_file_rejected_by_root(self):
        self.obsidian_release("1.15.0")
        real_prepare = worker.prepare

        def tamper(request, runner=None, http=None):
            out = real_prepare(request, runner, http)
            if out.get("artifact"):
                with open(out["artifact"]["path"], "ab") as fh:
                    fh.write(b"evil")
            return out
        with mock.patch.object(worker, "prepare", tamper):
            self.assertEqual(self.run_cli("update", "--yes", "--apps-only"), EXIT_PARTIAL)
        self.assertIn("changed after verification", self.out)
        self.assertEqual([m for m in self.sys.mutations() if "install" in m], [])

    def test_apt_managed_app_is_updated_by_apt_not_download(self):
        self.sys.install("chatgpt", "26.1")
        self.sys.offer("chatgpt", "26.1", VENDOR_REPO)
        self.run_cli("discover", euid=os.getuid())
        self.sys.offer("chatgpt", "26.2", VENDOR_REPO)
        self.obsidian_release("1.14.4")
        self.net.add(CHATGPT, b"should never be fetched")
        self.assertEqual(self.run_cli("update", "--yes"), EXIT_OK, self.out)
        self.assertEqual(self.sys.installed["chatgpt"][0], "26.2")
        self.assertNotIn(CHATGPT, [u for u, _ in self.net.requests])

    def test_flatpak_user_update_runs_as_user(self):
        self.sys.flatpak_updates["user"].add("com.discordapp.Discord")
        self.obsidian_release("1.14.4")
        with mock.patch.object(privilege, "_os", mock.Mock(getgroups=mock.Mock(return_value=[]),
                                                           umask=mock.Mock(return_value=0o22))):
            self.sys.worker = True
            code = self.run_cli("update", "discord", "--yes", sudo=True)
        self.assertEqual(code, EXIT_OK, self.out + self.err)
        upd = [c for c in self.sys.calls if c["argv"][:2] == [R.FLATPAK, "update"]][0]
        self.assertIn("--user", upd["argv"])
        self.assertEqual(upd["user_kwargs"]["user"], os.getuid())
        self.assertEqual(upd["env"]["HOME"], self.home)


class SudoModeTests(Harness):
    """Root acting for an invoking user: network work runs in a dropped child."""

    def test_worker_runs_as_invoking_user(self):
        self.base_system()
        self.init()
        self.obsidian_release("1.15.0")
        real_run = self.sys.run

        def run(argv, **kw):
            if argv[0] == sys.executable:
                self.worker_calls.append(kw)
                self.assertIn("-I", argv)
                out = worker.handle(json.loads(kw["input"]), runner=self.sys, http=self.http)
                return R.Result(argv, 0, json.dumps(out), "")
            return real_run(argv, **kw)
        fake_os = mock.Mock(getgroups=mock.Mock(return_value=[0]), umask=mock.Mock(return_value=0o22))
        with mock.patch.object(self.sys, "run", side_effect=run), mock.patch.object(privilege, "_os", fake_os):
            code = self.run_cli("update", "--yes", "--apps-only", sudo=True)
        self.assertEqual(code, EXIT_OK, self.out + self.err)
        self.assertTrue(self.worker_calls)
        for kw in self.worker_calls:
            self.assertEqual(kw["user_kwargs"]["user"], os.getuid())
            self.assertEqual(kw["env"]["HOME"], self.home)
        # Credentials were switched for user-file access and always restored.
        seteuid_calls = [c.args[0] for c in fake_os.seteuid.call_args_list]
        self.assertTrue(seteuid_calls)
        self.assertEqual(seteuid_calls.count(os.getuid()), seteuid_calls.count(0))
        self.assertEqual(self.sys.installed["obsidian"][0], "1.15.0")


class RegistrationTests(Harness):
    def test_add_url_registers_without_installing(self):
        self.init()
        data = make_deb(self.debs, "tool", "2.1-1")
        self.net.redirect("https://vendor.example/download/latest", "https://cdn.vendor.example/tool_2.1-1.deb")
        self.net.add("https://cdn.vendor.example/tool_2.1-1.deb", data)
        self.assertNotEqual(self.run_cli("add", "--url", "https://vendor.example/download/latest",
                                         euid=os.getuid()), EXIT_OK)
        self.assertIn("not an approved download host", self.err)
        code = self.run_cli("add", "--url", "https://vendor.example/download/latest",
                            "--allow-host", "cdn.vendor.example", "--name", "Tool", euid=os.getuid())
        self.assertEqual(code, EXIT_OK, self.err)
        app = self.cfg()["apps"]["tool"]
        self.assertEqual(app["identity"], {"package": "tool", "architecture": "amd64",
                                           "verified_on": app["identity"]["verified_on"]})
        self.assertEqual(app["verification"]["status"], "user-supplied")
        self.assertIn("source.url", app["provenance"]["user_supplied"])
        self.assertIn("id", app["provenance"]["inferred"])
        self.assertFalse(app["source"]["pinned"])
        self.assertEqual(self.sys.mutations(), [])
        self.assertIn("Nothing was installed", self.out)

    def test_versioned_url_is_marked_pinned(self):
        self.init()
        self.net.add("https://vendor.example/tool_2.1.deb", make_deb(self.debs, "tool", "2.1"))
        self.assertEqual(self.run_cli("add", "--url", "https://vendor.example/tool_2.1.deb", euid=os.getuid()), 0)
        self.assertTrue(self.cfg()["apps"]["tool"]["source"]["pinned"])
        self.assertIn("pinned", self.err)

    def test_download_page_maps_to_maintained_adapter(self):
        self.init()
        self.assertEqual(self.run_cli("add", "--url", "https://proton.me/mail/download", euid=os.getuid()), 0)
        self.assertEqual(self.cfg()["apps"]["proton-mail"]["source"]["resolver"], "vendor-json")
        self.assertEqual(self.net.requests, [])

    def test_remove_stops_tracking_without_uninstalling(self):
        self.base_system()
        self.init()
        self.assertEqual(self.run_cli("remove", "obsidian", euid=os.getuid()), EXIT_OK)
        self.assertNotIn("obsidian", self.cfg()["apps"])
        self.assertEqual(self.sys.mutations(), [])
        self.assertIn("NOT uninstalled", self.out)

    def test_install_missing_app_only_on_request(self):
        self.base_system()
        self.init()
        self.assertNotIn("proton-pass", self.cfg()["apps"])
        self.proton_manifest("1.43.0", installed=False)
        self.assertEqual(self.run_cli("install", "proton-pass", "--yes"), EXIT_OK, self.out + self.err)
        self.assertEqual(self.sys.installed["proton-pass"][0], "1.43.0")
        app = self.cfg()["apps"]["proton-pass"]
        self.assertEqual(app["provenance"]["install_origin"], "wardctl")
        self.assertIn("SHA-512 from vendor manifest", self.out)

    def test_install_url_rejects_html_page(self):
        self.init()
        self.net.add("https://vendor.example/download", b"<!DOCTYPE html><html>Get the app</html>")
        self.assertEqual(self.run_cli("install", "--url", "https://vendor.example/download", "--yes"), EXIT_FATAL)
        self.assertIn("does not serve a Debian package", self.err)
        self.assertEqual(self.sys.mutations(), [])

    def test_vendor_repo_app_not_configured_explains(self):
        self.init()
        self.assertEqual(self.run_cli("install", "sublime-text", "--yes"), EXIT_FATAL)
        self.assertIn("does not create or modify repositories", self.err)
        self.assertEqual(self.sys.mutations(), [])

    def test_unsupported_installer_types_are_never_run(self):
        self.init()
        self.assertEqual(self.run_cli("install", "private-internet-access", "--yes"), EXIT_FATAL)
        self.assertIn(".run", self.err)
        self.assertEqual(self.sys.mutations(), [])
        self.assertEqual(self.net.requests, [])

    def test_package_rename_requires_explicit_change(self):
        self.base_system()
        self.init()
        self.obsidian_release("1.15.0", package="obsidian-app")
        self.assertEqual(self.run_cli("update", "--yes", "--apps-only"), EXIT_PARTIAL)
        self.assertEqual(self.run_cli("set", "obsidian", "--package", "obsidian-app", euid=os.getuid()), 0)
        self.assertEqual(self.cfg()["apps"]["obsidian"]["packages"], ["obsidian-app"])


class ElevationTests(Harness):
    def test_mutating_command_reexecs_with_sudo(self):
        self.init()
        d = self.deps(euid=os.getuid())
        with mock.patch.object(privilege, "elevation_argv",
                               return_value=[R.SUDO, "--", "/usr/local/bin/wardctl", "update", "--yes"]):
            cli.main(["update", "--yes"], d)
        d.execv.assert_called_once_with(R.SUDO, [R.SUDO, "--", "/usr/local/bin/wardctl", "update", "--yes"])
        self.assertEqual(self.sys.mutations(), [])

    def test_read_only_commands_do_not_elevate(self):
        self.base_system()
        self.init()
        for cmd in (["status"], ["list"], ["check"], ["doctor"], ["update", "--dry-run"], []):
            self.obsidian_release("1.14.4")
            d = self.deps(euid=os.getuid())
            cli.main(cmd, d)
            d.execv.assert_not_called()

    def test_no_argument_output_explains_update(self):
        self.run_cli(euid=os.getuid())
        self.assertIn("sudo wardctl update", self.out)
        self.assertIn("wardctl init", self.out)

    def test_help_exit_codes(self):
        self.assertEqual(self.run_cli("--help", euid=os.getuid()), EXIT_OK)
        self.assertEqual(self.run_cli("bogus", euid=os.getuid()), 2)


if __name__ == "__main__":
    unittest.main()
