"""dpkg database queries, Debian version comparison and .deb inspection."""

import glob
import os
import re
from dataclasses import dataclass

from wardctl import runner as R
from wardctl.errors import WardctlError, VerificationError

DPKG_FIELDS = ("binary:Package", "Package", "Version", "Architecture", "db:Status-Abbrev",
               "Section", "Priority", "Maintainer", "Homepage")
_FORMAT = "\t".join("${%s}" % f for f in DPKG_FIELDS) + "\n"
# ar archive whose first member is debian-binary (padding after the name
# varies between tools: "debian-binary   " or GNU-style "debian-binary/  ").
DEB_MAGIC = b"!<arch>\ndebian-binary"


@dataclass
class InstalledPackage:
    name: str
    version: str
    arch: str
    status: str  # dpkg db:Status-Abbrev, e.g. "ii ", "hi "
    section: str = ""
    priority: str = ""
    maintainer: str = ""
    homepage: str = ""

    @property
    def installed(self):
        return len(self.status) >= 2 and self.status[1] == "i"

    @property
    def held(self):
        return self.status[:1] == "h"

    @property
    def broken(self):
        return len(self.status) >= 3 and self.status[2] not in (" ", "")


def query_installed(runner, packages=None):
    """Return {package name: InstalledPackage} from the dpkg database.
    Only fully or partially installed entries are returned. This is the
    authoritative source for installed versions; cached state is not."""
    argv = [R.DPKG_QUERY, "-W", "-f=" + _FORMAT]
    if packages:
        argv.append("--")
        argv.extend(packages)
    res = runner.run(argv)
    # dpkg-query exits 1 when some named packages are unknown; output is still valid.
    if res.returncode not in (0, 1):
        raise WardctlError(f"dpkg-query failed: {res.stderr.strip()}")
    result = {}
    for line in res.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) != len(DPKG_FIELDS):
            continue
        binary, name, version, arch, status, section, prio, maint, home = parts
        pkg = InstalledPackage(name, version, arch, status, section, prio, maint, home)
        if not pkg.installed:
            continue
        # Prefer the native-architecture instance when multiarch copies exist.
        if name in result and ":" in binary:
            continue
        result[name] = pkg
    return result


def desktop_file_owners(runner, pattern="/usr/share/applications/*.desktop"):
    """Return the set of packages that ship a desktop launcher."""
    files = sorted(glob.glob(pattern))
    owners = set()
    for i in range(0, len(files), 200):
        res = runner.run([R.DPKG_QUERY, "-S", "--", *files[i:i + 200]])
        for line in res.stdout.splitlines():
            if line.startswith(("diversion by", "local diversion")) or ": " not in line:
                continue
            pkgs = line.split(": ", 1)[0]
            for pkg in pkgs.split(","):
                owners.add(pkg.strip().split(":")[0])
    return owners


class VersionComparer:
    """Debian version comparison via `dpkg --compare-versions` (handles
    epochs, upstream versions and Debian revisions exactly as dpkg does)."""

    def __init__(self, runner):
        self.runner = runner
        self._cache = {}

    def _rel(self, a, op, b):
        key = (a, op, b)
        if key not in self._cache:
            res = self.runner.run([R.DPKG, "--compare-versions", a, op, b])
            if res.returncode not in (0, 1):
                raise WardctlError(f"cannot compare versions {a!r} and {b!r}: {res.stderr.strip()}")
            self._cache[key] = res.returncode == 0
        return self._cache[key]

    def compare(self, a, b):
        if a == b:
            return 0
        if self._rel(a, "lt", b):
            return -1
        if self._rel(a, "gt", b):
            return 1
        return 0

    def newest(self, versions):
        best = None
        for v in versions:
            if best is None or self.compare(v, best) > 0:
                best = v
        return best


VALID_VERSION = re.compile(r"^(\d+:)?[0-9][A-Za-z0-9.+~:-]*$")


@dataclass
class DebInfo:
    package: str
    version: str
    arch: str


def looks_like_deb(head):
    return head.startswith(DEB_MAGIC)


def inspect_deb(runner, path, user_kwargs=None):
    """Validate that `path` is a Debian binary package and return its
    identity. Rejects HTML or other content served under a .deb name before
    handing it to dpkg-deb."""
    with open(path, "rb") as fh:
        head = fh.read(64)
    if not looks_like_deb(head):
        snippet = head[:16].decode("latin-1", "replace")
        lowered = head.lstrip().lower()
        hint = " (looks like an HTML page)" if lowered.startswith((b"<!doctype", b"<html", b"<?xml", b"<head")) else ""
        raise VerificationError(f"download is not a Debian package{hint}; starts with {snippet!r}")
    res = runner.run([R.DPKG_DEB, "--field", path, "Package", "Version", "Architecture"],
                     user_kwargs=user_kwargs)
    if not res.ok:
        raise VerificationError(f"dpkg-deb could not read the package control data: {res.stderr.strip()}")
    fields = {}
    for line in res.stdout.splitlines():
        key, sep, value = line.partition(":")
        if sep:
            fields[key.strip()] = value.strip()
    pkg, ver, arch = fields.get("Package", ""), fields.get("Version", ""), fields.get("Architecture", "")
    if not re.match(r"^[a-z0-9][a-z0-9.+-]+$", pkg) or not VALID_VERSION.match(ver) or not arch:
        raise VerificationError(f"package control data is incomplete or invalid: {fields}")
    return DebInfo(pkg, ver, arch)


def arch_compatible(deb_arch, system_arch):
    return deb_arch in (system_arch, "all")


def check_identity(info, app, system_arch):
    """Enforce the registered identity of an application's package."""
    if not arch_compatible(info.arch, system_arch):
        raise VerificationError(
            f"{info.package} {info.version} is built for {info.arch}, this system is {system_arch}; refusing to install")
    allowed_archs = app.get("architectures") or []
    if allowed_archs and info.arch != "all" and info.arch not in allowed_archs:
        raise VerificationError(f"architecture {info.arch} is not allowed for {app['id']} ({', '.join(allowed_archs)})")
    expected = (app.get("identity") or {}).get("package") or (app.get("packages") or [None])[0]
    if expected and info.package != expected:
        raise VerificationError(
            f"downloaded package is {info.package!r} but {app['id']} is registered as {expected!r}",
            hint=f"If the vendor legitimately renamed the package, run "
                 f"`wardctl set {app['id']} --package {info.package}` to change the registration.")


def reboot_required():
    return os.path.exists("/run/reboot-required")
