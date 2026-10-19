"""HTTPS fetching, redirect validation and release resolvers (fixture HTTP)."""

import json
import os
import socket
import tempfile
import unittest

from helpers import FakeTransport, make_deb, needs_dpkg

from wardctl import debpkg, resolvers
from wardctl.errors import FetchError, HostRejected, ResolveError
from wardctl.netfetch import HttpClient, redact
from wardctl.runner import Runner

GH = ["api.github.com", "github.com", "release-assets.githubusercontent.com"]


def client(t):
    return HttpClient(transport=t, retries=3, sleep=lambda s: None)


class FetchTests(unittest.TestCase):
    def test_https_required(self):
        with self.assertRaises(HostRejected):
            client(FakeTransport()).get_bytes("http://vendor.example/x", ["vendor.example"])

    def test_https_to_http_redirect_rejected(self):
        t = FakeTransport()
        t.redirect("https://vendor.example/latest.deb", "http://vendor.example/app_2.deb")
        with self.assertRaises(HostRejected) as cm:
            client(t).get_bytes("https://vendor.example/latest.deb", ["vendor.example"])
        self.assertIn("HTTPS", str(cm.exception))
        self.assertEqual(len(t.requests), 1)  # never connected to the HTTP URL

    def test_redirect_to_unapproved_host_rejected_before_connecting(self):
        t = FakeTransport()
        t.redirect("https://vendor.example/latest.deb", "https://evil.example/app.deb")
        with self.assertRaises(HostRejected):
            client(t).get_bytes("https://vendor.example/latest.deb", ["vendor.example"])
        self.assertNotIn("https://evil.example/app.deb", [u for u, _ in t.requests])

    def test_approved_cdn_redirect_followed(self):
        t = FakeTransport()
        t.redirect("https://github.com/o/r/releases/download/v1/a.deb",
                   "https://release-assets.githubusercontent.com/x?sig=SECRET")
        t.add("https://release-assets.githubusercontent.com/x?sig=SECRET", b"data")
        c = client(t)
        final, data = c.get_bytes("https://github.com/o/r/releases/download/v1/a.deb", GH)
        self.assertEqual(data, b"data")
        self.assertTrue(all("SECRET" not in line for line in c.log))

    def test_relative_redirect_and_limit(self):
        t = FakeTransport()
        for i in range(10):
            t.redirect(f"https://v.example/{i}", f"/{i + 1}")
        with self.assertRaises(FetchError) as cm:
            client(t).get_bytes("https://v.example/0", ["v.example"])
        self.assertIn("too many redirects", str(cm.exception))

    def test_credentials_and_ports_refused(self):
        for url in ("https://user:pw@v.example/x", "https://v.example:8443/x"):
            with self.subTest(url=url), self.assertRaises(HostRejected):
                client(FakeTransport()).get_bytes(url, ["v.example"])

    def test_retries_transient_errors_then_succeeds(self):
        t = FakeTransport()
        t.error("https://v.example/x", socket.timeout("timed out"), then_body=b"ok")
        self.assertEqual(client(t).get_bytes("https://v.example/x", ["v.example"])[1], b"ok")

    def test_persistent_network_error(self):
        t = FakeTransport()
        t.error("https://v.example/x", ConnectionResetError("reset"))
        with self.assertRaises(FetchError) as cm:
            client(t).get_bytes("https://v.example/x", ["v.example"])
        self.assertIn("network error", str(cm.exception))
        self.assertEqual(len(t.requests), 3)

    def test_http_errors_not_retried(self):
        t = FakeTransport()
        with self.assertRaises(FetchError):
            client(t).get_bytes("https://v.example/missing", ["v.example"])
        self.assertEqual(len(t.requests), 1)

    def test_download_size_limit_and_cleanup(self):
        t = FakeTransport()
        t.add("https://v.example/big.deb", b"x" * 5000)
        with tempfile.TemporaryDirectory() as d:
            dest = os.path.join(d, "f.deb")
            with self.assertRaises(FetchError):
                client(t).download("https://v.example/big.deb", ["v.example"], dest, 1000)
            self.assertFalse(os.path.exists(dest))
            res = client(t).download("https://v.example/big.deb", ["v.example"], dest, 10000)
            self.assertEqual(res.size, 5000)
            self.assertEqual(oct(os.stat(dest).st_mode & 0o777), "0o600")

    def test_peek_uses_range(self):
        t = FakeTransport()
        t.add("https://v.example/a.deb", b"y" * 10000)
        _, head = client(t).peek("https://v.example/a.deb", ["v.example"], 100)
        self.assertEqual(len(head), 100)
        self.assertEqual(t.requests[0][1]["Range"], "bytes=0-99")
        t.honor_range = False
        _, head = client(t).peek("https://v.example/a.deb", ["v.example"], 100)
        self.assertEqual(len(head), 100)

    def test_redact(self):
        self.assertEqual(redact("https://h.example/p?token=abc"), "https://h.example/p?…")


def gh_release(tag, assets, draft=False, prerelease=False, repo="obsidianmd/obsidian-releases"):
    return {"tag_name": tag, "draft": draft, "prerelease": prerelease,
            "assets": [{"name": n, "browser_download_url": f"https://github.com/{repo}/releases/download/{tag}/{n}",
                        "digest": "sha256:" + "a" * 64} for n in assets]}


class ResolverTests(unittest.TestCase):
    def ctx(self, t):
        cmp = debpkg.VersionComparer(Runner())
        return resolvers.ResolveContext(http=client(t), arch="amd64", debian_major="13", comparer=cmp)

    def gh_source(self, **kw):
        src = {"resolver": "github-release", "repo": "obsidianmd/obsidian-releases",
               "asset_pattern": r"obsidian_[0-9][0-9.]*_{arch}\.deb", "approved_hosts": GH}
        src.update(kw)
        return src

    def test_github_skips_prereleases_and_drafts(self):
        t = FakeTransport()
        t.add(resolvers.GitHubReleaseResolver.API.format(repo="obsidianmd/obsidian-releases"), json.dumps([
            gh_release("v2.0.0", ["obsidian_2.0.0_amd64.deb"], prerelease=True),
            gh_release("v1.9.9", ["obsidian_1.9.9_amd64.deb"], draft=True),
            gh_release("v1.14.4", ["obsidian_1.14.4_amd64.deb", "obsidian_1.14.4_arm64.deb", "x.AppImage"]),
        ]).encode())
        rel = resolvers.resolve(self.gh_source(), self.ctx(t))
        self.assertEqual(rel.label, "v1.14.4")
        self.assertTrue(rel.url.endswith("obsidian_1.14.4_amd64.deb"))
        self.assertEqual(rel.checksums["sha256"], "a" * 64)
        self.assertIsNone(rel.version)  # version comes from control data, not the tag

    def test_github_newest_without_asset_falls_back_with_note(self):
        t = FakeTransport()
        t.add(resolvers.GitHubReleaseResolver.API.format(repo="obsidianmd/obsidian-releases"), json.dumps([
            gh_release("v1.13.8", ["Obsidian-1.13.8.AppImage"]),
            gh_release("v1.13.7", ["obsidian_1.13.7_amd64.deb"])]).encode())
        rel = resolvers.resolve(self.gh_source(), self.ctx(t))
        self.assertEqual(rel.label, "v1.13.7")
        self.assertIn("v1.13.8", rel.notes[0])

    def test_github_ambiguous_assets_refused(self):
        t = FakeTransport()
        t.add(resolvers.GitHubReleaseResolver.API.format(repo="obsidianmd/obsidian-releases"), json.dumps([
            gh_release("v1", ["obsidian_1_amd64.deb", "obsidian_1.0_amd64.deb"])]).encode())
        with self.assertRaises(ResolveError):
            resolvers.resolve(self.gh_source(), self.ctx(t))

    def test_github_signature_asset(self):
        repo = "veracrypt/VeraCrypt"
        t = FakeTransport()
        t.add(resolvers.GitHubReleaseResolver.API.format(repo=repo), json.dumps([gh_release(
            "VeraCrypt_1.26.29", ["veracrypt-1.26.29-Debian-13-amd64.deb", "veracrypt-1.26.29-Debian-13-amd64.deb.sig",
                                  "veracrypt-1.26.29-Debian-12-amd64.deb", "veracrypt-console-1.26.29-Debian-13-amd64.deb"],
            repo=repo)]).encode())
        src = self.gh_source(repo=repo, asset_pattern=r"veracrypt-[0-9][0-9.]*-Debian-{debian_major}-{arch}\.deb",
                             signature={"suffix": ".sig", "keyring": "veracrypt"})
        rel = resolvers.resolve(src, self.ctx(t))
        self.assertTrue(rel.url.endswith("Debian-13-amd64.deb"))
        self.assertTrue(rel.signature_url.endswith(".deb.sig"))
        self.assertEqual(rel.keyring, "veracrypt")

    def test_github_asset_url_must_belong_to_repo(self):
        t = FakeTransport()
        bad = gh_release("v1", ["obsidian_1.0_amd64.deb"])
        bad["assets"][0]["browser_download_url"] = "https://github.com/someone/else/releases/download/v1/x.deb"
        t.add(resolvers.GitHubReleaseResolver.API.format(repo="obsidianmd/obsidian-releases"),
              json.dumps([bad]).encode())
        with self.assertRaises(ResolveError):
            resolvers.resolve(self.gh_source(), self.ctx(t))

    def proton(self, releases):
        t = FakeTransport()
        t.add("https://proton.me/download/mail/linux/version.json", json.dumps({"Releases": releases}).encode())
        src = {"resolver": "vendor-json", "format": "proton-version-json", "channel": "Stable",
               "url": "https://proton.me/download/mail/linux/version.json", "approved_hosts": ["proton.me"]}
        return resolvers.resolve(src, self.ctx(t))

    def entry(self, cat, ver, rollout=1, key="RolloutProportion"):
        return {"CategoryName": cat, "Version": ver, key: rollout, "File": [
            {"Identifier": ".deb (Ubuntu/Debian)", "Url": f"https://proton.me/download/mail/linux/{ver}/P.deb",
             "Sha512CheckSum": "b" * 128},
            {"Identifier": ".rpm", "Url": f"https://proton.me/download/mail/linux/{ver}/P.rpm"}]}

    def test_proton_channel_and_rollout(self):
        rel = self.proton([self.entry("Alpha", "1.15.1"), self.entry("EarlyAccess", "1.15.0"),
                           self.entry("Stable", "1.14.1", 0.2), self.entry("Stable", "1.14.0"),
                           self.entry("Stable", "1.13.4")])
        self.assertEqual(rel.version, "1.14.0")
        self.assertEqual(rel.checksums["sha512"], "b" * 128)
        self.assertTrue(rel.url.endswith("/1.14.0/P.deb"))

    def test_proton_no_eligible_release(self):
        with self.assertRaises(ResolveError):
            self.proton([self.entry("Beta", "2.0")])

    def test_direct_and_pinned(self):
        src = {"resolver": "direct-deb", "url": "https://v.example/latest/app_{arch}.deb",
               "approved_hosts": ["v.example"]}
        rel = resolvers.resolve(src, self.ctx(FakeTransport()))
        self.assertEqual(rel.url, "https://v.example/latest/app_amd64.deb")
        self.assertFalse(rel.pinned)
        src["pinned"] = True
        self.assertIn("pinned", resolvers.resolve(src, self.ctx(FakeTransport())).notes[0])

    def html(self, body):
        t = FakeTransport()
        t.add("https://v.example/download", body.encode())
        src = {"resolver": "html-link", "page_url": "https://v.example/download",
               "link_pattern": r"https://v\.example/files/app_[0-9.]+_{arch}\.deb", "approved_hosts": ["v.example"]}
        return resolvers.resolve(src, self.ctx(t))

    def test_html_adapter_requires_exactly_one_link(self):
        rel = self.html('<a href="/files/app_1.2_amd64.deb">deb</a><a href="/files/app_1.2_arm64.deb">arm</a>')
        self.assertEqual(rel.url, "https://v.example/files/app_1.2_amd64.deb")
        with self.assertRaises(ResolveError) as cm:
            self.html('<a href="/files/app_1.2_amd64.deb"></a><a href="/files/app_1.10_amd64.deb"></a>')
        self.assertIn("refusing to guess", str(cm.exception))
        with self.assertRaises(ResolveError):
            self.html("<script>render()</script>")


@needs_dpkg
class WorkerTests(unittest.TestCase):
    """The unprivileged preparation step, end to end over fixture HTTP."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, self.dir, True)

    def request(self, app, mode):
        return {"task": "prepare", "app": app, "mode": mode, "arch": "amd64", "debian_major": "13",
                "staging_dir": self.dir, "max_bytes": 10 ** 7}

    def app(self, url="https://v.example/latest.deb"):
        return {"id": "tool", "packages": ["tool"], "architectures": ["amd64"],
                "source": {"resolver": "direct-deb", "url": url, "approved_hosts": ["v.example"]}}

    def test_peek_reads_version_without_full_download(self):
        from wardctl import worker
        data = make_deb(self.dir, "tool", "2.0-1")
        t = FakeTransport()
        t.add("https://v.example/latest.deb", data)
        out = worker.handle(self.request(self.app(), "metadata"), runner=Runner(), http=client(t))
        self.assertEqual(out["control"]["version"], "2.0-1")
        self.assertIsNone(out["artifact"])
        self.assertEqual([f for f in os.listdir(self.dir) if f.startswith("prep-")], [])

    def test_html_served_as_deb_rejected(self):
        from wardctl import worker
        from wardctl.errors import VerificationError
        t = FakeTransport()
        t.add("https://v.example/latest.deb", b"<!doctype html><title>Login</title>")
        with self.assertRaises(VerificationError):
            worker.handle(self.request(self.app(), "download"), runner=Runner(), http=client(t))
        self.assertEqual([f for f in os.listdir(self.dir) if f.startswith("prep-")], [])

    def test_wrong_package_identity_rejected(self):
        from wardctl import worker
        from wardctl.errors import VerificationError
        t = FakeTransport()
        t.add("https://v.example/latest.deb", make_deb(self.dir, "other-tool", "2.0"))
        with self.assertRaises(VerificationError):
            worker.handle(self.request(self.app(), "download"), runner=Runner(), http=client(t))

    def test_wrong_architecture_rejected(self):
        from wardctl import worker
        from wardctl.errors import VerificationError
        t = FakeTransport()
        t.add("https://v.example/latest.deb", make_deb(self.dir, "tool", "2.0", arch="arm64"))
        with self.assertRaises(VerificationError):
            worker.handle(self.request(self.app(), "metadata"), runner=Runner(), http=client(t))

    def test_published_checksum_mismatch_rejected(self):
        from wardctl import worker
        from wardctl.errors import VerificationError
        data = make_deb(self.dir, "proton-mail", "1.14.0")
        t = FakeTransport()
        t.add("https://proton.me/download/mail/linux/version.json", json.dumps({"Releases": [{
            "CategoryName": "Stable", "Version": "1.14.0", "RolloutProportion": 1, "File": [
                {"Url": "https://proton.me/download/mail/linux/1.14.0/P.deb", "Sha512CheckSum": "c" * 128}]}]}).encode())
        t.add("https://proton.me/download/mail/linux/1.14.0/P.deb", data)
        app = {"id": "proton-mail", "packages": ["proton-mail"], "architectures": ["amd64"],
               "source": {"resolver": "vendor-json", "format": "proton-version-json", "channel": "Stable",
                          "url": "https://proton.me/download/mail/linux/version.json", "approved_hosts": ["proton.me"]}}
        with self.assertRaises(VerificationError) as cm:
            worker.handle(self.request(app, "download"), runner=Runner(), http=client(t))
        self.assertIn("SHA512 mismatch", str(cm.exception))

    def test_manifest_version_must_match_package(self):
        import hashlib
        from wardctl import worker
        from wardctl.errors import VerificationError
        data = make_deb(self.dir, "proton-mail", "1.13.0")
        t = FakeTransport()
        t.add("https://proton.me/m.json", json.dumps({"Releases": [{
            "CategoryName": "Stable", "Version": "1.14.0", "File": [
                {"Url": "https://proton.me/P.deb", "Sha512CheckSum": hashlib.sha512(data).hexdigest()}]}]}).encode())
        t.add("https://proton.me/P.deb", data)
        app = {"id": "proton-mail", "packages": ["proton-mail"], "architectures": ["amd64"],
               "source": {"resolver": "vendor-json", "format": "proton-version-json", "url": "https://proton.me/m.json",
                          "approved_hosts": ["proton.me"]}}
        with self.assertRaises(VerificationError):
            worker.handle(self.request(app, "download"), runner=Runner(), http=client(t))

    def test_probe_rejects_web_page(self):
        from wardctl import worker
        t = FakeTransport()
        t.add("https://v.example/download", b"<html>Click to download</html>")
        with self.assertRaises(ResolveError) as cm:
            worker.handle({"task": "probe", "url": "https://v.example/download", "arch": "amd64",
                           "debian_major": "13", "allowed_hosts": []}, runner=Runner(), http=client(t))
        self.assertIn("arbitrary pages", cm.exception.hint)


@unittest.skipUnless(__import__("helpers").HAVE_GPG, "gpg not available")
@needs_dpkg
class SignatureTests(unittest.TestCase):
    def test_gpgv_good_and_bad_signature(self):
        import shutil
        import subprocess
        from unittest import mock
        from wardctl import verify
        from wardctl.errors import VerificationError
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        gnupg = os.path.join(d, "gnupg")
        os.mkdir(gnupg, 0o700)
        env = dict(os.environ, GNUPGHOME=gnupg)
        subprocess.run(["gpg", "--batch", "--passphrase", "", "--quick-gen-key", "test@example.invalid",
                        "ed25519", "sign", "never"], env=env, check=True, capture_output=True)
        keys = os.path.join(d, "keys")
        os.mkdir(keys)
        with open(os.path.join(keys, "testkey.gpg"), "wb") as fh:
            fh.write(subprocess.run(["gpg", "--export"], env=env, check=True, capture_output=True).stdout)
        data = os.path.join(d, "a.deb")
        with open(data, "wb") as fh:
            fh.write(b"payload")
        subprocess.run(["gpg", "--batch", "--detach-sign", "-o", data + ".sig", data], env=env, check=True,
                       capture_output=True)
        with mock.patch.object(verify, "KEY_DIR", keys):
            self.assertTrue(verify.check_signature(Runner(), "testkey", data + ".sig", data))
            with open(data, "ab") as fh:
                fh.write(b"tampered")
            with self.assertRaises(VerificationError):
                verify.check_signature(Runner(), "testkey", data + ".sig", data)

    def test_bundled_veracrypt_keyring_present(self):
        from wardctl import verify
        self.assertTrue(os.path.getsize(verify.keyring_path("veracrypt")) > 1000)


if __name__ == "__main__":
    unittest.main()
