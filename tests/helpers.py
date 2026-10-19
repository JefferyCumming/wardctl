"""Test doubles: a simulated dpkg/APT system, an HTTP fixture transport and
helpers to build real (tiny) .deb files with dpkg-deb.

Only read-only tools run for real: `dpkg --compare-versions`, `dpkg-deb`
(building/inspecting files in temp dirs) and `gpgv`. Everything that would
change the machine (apt-get update/upgrade/install, flatpak update) is
simulated and recorded.
"""

import io
import os
import pwd
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from wardctl import runner as R  # noqa: E402
from wardctl.identity import MODE_ROOT, MODE_USER, Identity  # noqa: E402
from wardctl.netfetch import RawResponse  # noqa: E402
from wardctl.platforminfo import PlatformInfo  # noqa: E402

HAVE_DPKG = shutil.which("dpkg-deb") is not None and shutil.which("dpkg") is not None
HAVE_GPG = shutil.which("gpg") is not None and shutil.which("gpgv") is not None
needs_dpkg = unittest.skipUnless(HAVE_DPKG, "dpkg tools not available")

DEBIAN13 = PlatformInfo("debian", "13", "trixie", "amd64", "Debian GNU/Linux 13 (trixie)")
DEBIAN_REPO = "http://deb.debian.org/debian trixie/main amd64 Packages"
VENDOR_REPO = "https://vendor.example/apt stable/main amd64 Packages"


def make_identity(home, mode=MODE_USER):
    return Identity(uid=os.getuid(), gid=os.getgid(), name=pwd.getpwuid(os.getuid()).pw_name,
                    home=home, mode=mode, groups=(os.getgid(),))


def fake_pw(home, uid=None, name=None):
    uid = os.getuid() if uid is None else uid
    return pwd.struct_passwd((name or pwd.getpwuid(os.getuid()).pw_name, "x", uid, os.getgid(),
                              "", home, "/bin/sh"))


def make_deb(directory, package, version, arch="amd64", name=None):
    root = tempfile.mkdtemp(dir=directory)
    os.makedirs(os.path.join(root, "DEBIAN"))
    with open(os.path.join(root, "DEBIAN", "control"), "w") as fh:
        fh.write(f"Package: {package}\nVersion: {version}\nArchitecture: {arch}\n"
                 f"Maintainer: Test <test@example.invalid>\nDescription: test package\n")
    os.makedirs(os.path.join(root, "usr", "share", "doc", package))
    with open(os.path.join(root, "usr", "share", "doc", package, "README"), "w") as fh:
        fh.write("x" * 100)
    out = os.path.join(directory, name or f"{package}_{version.replace(':', '%3a')}_{arch}.deb")
    subprocess.run(["dpkg-deb", "--root-owner-group", "-Zgzip", "--build", root, out], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    shutil.rmtree(root)
    with open(out, "rb") as fh:
        return fh.read()


class FakeSystem:
    """In-memory dpkg database + APT repositories behind a fake Runner."""

    def __init__(self, arch="amd64"):
        self.arch = arch
        self.installed = {}       # name -> (version, arch, status, maintainer, homepage, section)
        self.repo = {}            # name -> [(version, source_desc)]
        self.origins = {DEBIAN_REPO: "Debian", VENDOR_REPO: "Vendor"}
        self.holds = set()
        self.desktop = set()
        self.flatpaks = {}        # (app_id, inst) -> version
        self.flatpak_updates = {"user": set(), "system": set()}
        self.fail = {}            # "refresh"/"upgrade"/"install" -> returncode
        self.sim_text = None
        self.calls = []
        self.real = R.Runner()
        self.on_install = None    # optional hook(argv)

    # -- state helpers
    def install(self, name, version, arch="amd64", maintainer="Vendor <v@example.invalid>",
                homepage="", section="misc", status="ii "):
        self.installed[name] = (version, arch, status, maintainer, homepage, section)

    def offer(self, name, version, source=DEBIAN_REPO):
        self.repo.setdefault(name, []).append((version, source))

    def hold(self, name):
        self.holds.add(name)
        v = self.installed[name]
        self.installed[name] = (v[0], v[1], "hi ", *v[3:])

    # -- command handling
    def exists(self, path):
        return True

    def _res(self, argv, rc=0, out="", err=""):
        return R.Result(list(argv), rc, out, err)

    def _cmp(self, a, op, b):
        return subprocess.run(["dpkg", "--compare-versions", a, op, b]).returncode == 0

    def newest(self, versions):
        best = None
        for v in versions:
            if best is None or self._cmp(v, "gt", best):
                best = v
        return best

    def policy_block(self, name):
        inst = self.installed.get(name)
        repo = self.repo.get(name, [])
        if not inst and not repo:
            return ""
        versions = {}
        for v, src in repo:
            versions.setdefault(v, []).append((500, src))
        if inst:
            versions.setdefault(inst[0], []).append((100, "/var/lib/dpkg/status"))
        cand = self.newest([v for v, _ in repo]) if repo else (inst[0] if inst else None)
        lines = [f"{name}:", f"  Installed: {inst[0] if inst else '(none)'}",
                 f"  Candidate: {cand or '(none)'}", "  Version table:"]
        for v, srcs in versions.items():
            mark = " ***" if inst and v == inst[0] else "    "
            lines.append(f"{mark} {v} {max(p for p, _ in srcs)}")
            for prio, src in srcs:
                lines.append(f"        {prio} {src}")
        return "\n".join(lines) + "\n"

    def run(self, argv, interactive=False, env=None, input=None, cwd=None, user_kwargs=None, timeout=None):
        argv = list(argv)
        self.calls.append({"argv": argv, "interactive": interactive, "env": env, "user_kwargs": user_kwargs,
                           "input": input})
        exe = argv[0]
        if exe == R.DPKG and argv[1:2] == ["--print-architecture"]:
            return self._res(argv, 0, self.arch + "\n")
        if exe in (R.DPKG, R.DPKG_DEB, R.GPGV):
            return self.real.run(argv, env=env, input=input, cwd=cwd)
        if exe == R.DPKG_QUERY and argv[1] == "-W":
            names = argv[argv.index("--") + 1:] if "--" in argv else sorted(self.installed)
            out, rc = [], 0
            for n in names:
                if n not in self.installed:
                    rc = 1
                    continue
                v, a, st, m, h, sec = self.installed[n]
                out.append("\t".join([n, n, v, a, st, sec, "optional", m, h]))
            return self._res(argv, rc, "\n".join(out) + ("\n" if out else ""))
        if exe == R.DPKG_QUERY and argv[1] == "-S":
            lines = [f"{p}: /usr/share/applications/{p}.desktop" for p in sorted(self.desktop)]
            return self._res(argv, 0, "\n".join(lines))
        if exe == R.APT_CACHE and argv[1:2] == ["policy"]:
            if len(argv) == 2:
                text = " 100 /var/lib/dpkg/status\n     release a=now\n"
                for desc, origin in self.origins.items():
                    text += f" 500 {desc}\n     release o={origin},a=stable\n"
                return self._res(argv, 0, "Package files:\n" + text)
            names = argv[argv.index("--") + 1:]
            return self._res(argv, 0, "".join(self.policy_block(n) for n in names))
        if exe == R.APT_MARK and argv[1] == "showhold":
            return self._res(argv, 0, "\n".join(sorted(self.holds)))
        if exe == R.FLATPAK:
            return self._flatpak(argv)
        if exe == R.APT_GET:
            return self._apt_get(argv)
        if exe == sys.executable:
            raise AssertionError("worker subprocess should be handled by the test")
        raise AssertionError(f"unexpected command: {argv}")

    def _flatpak(self, argv):
        inst = "user" if "--user" in argv else "system"
        if argv[1] == "list":
            rows = [f"{a}\t{v}" for (a, i), v in self.flatpaks.items() if i == inst]
            return self._res(argv, 0, "\n".join(rows))
        if argv[1] == "remote-ls":
            return self._res(argv, 0, "\n".join(sorted(self.flatpak_updates[inst])))
        if argv[1] == "update":
            return self._res(argv, self.fail.get("flatpak", 0))
        raise AssertionError(argv)

    def upgradable(self):
        res = []
        for n, (v, *_rest) in sorted(self.installed.items()):
            if n in self.holds or n not in self.repo:
                continue
            best = self.newest([rv for rv, _ in self.repo[n]])
            if self._cmp(best, "gt", v):
                res.append((n, v, best))
        return res

    def _apt_get(self, argv):
        if "-s" in argv:
            if self.sim_text is not None:
                return self._res(argv, 0, self.sim_text)
            lines = [f"Inst {n} [{v}] ({b} Debian:13/stable [amd64])" for n, v, b in self.upgradable()]
            return self._res(argv, 0, "\n".join(lines) + "\n")
        if "update" in argv:
            return self._res(argv, self.fail.get("refresh", 0))
        if argv[-1] in ("upgrade", "full-upgrade"):
            rc = self.fail.get("upgrade", 0)
            if rc == 0:
                for n, _v, b in self.upgradable():
                    self.install(n, b, *self.installed[n][1:2])
            return self._res(argv, rc)
        if "install" in argv:
            rc = self.fail.get("install", 0)
            targets = argv[argv.index("--") + 1:]
            if self.on_install:
                self.on_install(argv)
            if rc == 0:
                for t in targets:
                    if t.endswith(".deb"):
                        res = self.real.run([R.DPKG_DEB, "--field", t, "Package", "Version", "Architecture"])
                        f = dict(line.split(": ", 1) for line in res.stdout.splitlines())
                        self.install(f["Package"], f["Version"], f["Architecture"])
                    elif t in self.repo:
                        self.install(t, self.newest([rv for rv, _ in self.repo[t]]))
            return self._res(argv, rc)
        raise AssertionError(argv)

    def commands(self, exe=None):
        return [c["argv"] for c in self.calls if exe is None or c["argv"][0] == exe]

    def mutations(self):
        """Calls that would modify the real system."""
        out = []
        for c in self.calls:
            a = c["argv"]
            if a[0] == R.APT_GET and "-s" not in a:
                out.append(a)
            if a[0] == R.FLATPAK and a[1] == "update":
                out.append(a)
        return out


class _Body:
    def __init__(self, data, fail_after=None):
        self.buf = io.BytesIO(data)
        self.closed = False

    def read(self, n=-1):
        return self.buf.read(n)

    def close(self):
        self.closed = True


class FakeTransport:
    def __init__(self):
        self.routes = {}
        self.requests = []
        self.honor_range = True

    def add(self, url, body=b"", status=200, headers=None):
        self.routes[url] = [("ok", status, body, headers or {})]

    def redirect(self, url, location, status=302):
        self.routes[url] = [("ok", status, b"", {"location": location})]

    def error(self, url, exc, then_body=None):
        seq = [("err", exc)]
        if then_body is not None:
            seq.append(("ok", 200, then_body, {}))
        self.routes[url] = seq

    def open(self, method, url, headers):
        self.requests.append((url, dict(headers)))
        if url not in self.routes:
            return RawResponse(404, {}, _Body(b"not found"))
        seq = self.routes[url]
        item = seq.pop(0) if len(seq) > 1 else seq[0]
        if item[0] == "err":
            raise item[1]
        _, status, body, hdrs = item
        hdrs = {k.lower(): v for k, v in hdrs.items()}
        rng = headers.get("Range")
        if rng and status == 200 and self.honor_range:
            end = int(rng.split("-")[1])
            body = body[:end + 1]
            status = 206
        elif status == 200 and "content-length" not in hdrs:
            hdrs["content-length"] = str(len(body))
        return RawResponse(status, hdrs, _Body(body))


class TempHomeCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mrupd-test-")
        self.home = os.path.join(self.tmp, "home")
        os.mkdir(self.home, 0o755)
        self.addCleanup(shutil.rmtree, self.tmp, True)
