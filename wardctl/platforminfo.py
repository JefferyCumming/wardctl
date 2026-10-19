"""Distribution and architecture detection.

Only combinations listed in SUPPORTED have been tested. Adding one is a
deliberate change: extend SUPPORTED and the catalog's per-architecture
source entries, then test on that system.
"""

from dataclasses import dataclass

from wardctl import runner as R
from wardctl.errors import UnsupportedPlatform

# (os-release ID, VERSION_ID) -> tested dpkg architectures
SUPPORTED = {("debian", "13"): ("amd64",)}


@dataclass(frozen=True)
class PlatformInfo:
    distro: str
    version_id: str
    codename: str
    arch: str
    pretty: str

    @property
    def supported(self):
        return self.arch in SUPPORTED.get((self.distro, self.version_id), ())

    @property
    def debian_major(self):
        return self.version_id.split(".")[0]

    def describe(self):
        return f"{self.pretty} ({self.arch})"

    def require_supported(self, operation="this operation"):
        if self.supported:
            return
        tested = ", ".join(f"{d} {v} {'/'.join(a)}" for (d, v), a in SUPPORTED.items())
        raise UnsupportedPlatform(
            f"{operation} is not supported on {self.describe()}.",
            hint=f"wardctl has only been tested on: {tested}. Read-only commands "
                 "(list, status, doctor) still work.")


def parse_os_release(text):
    values = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key.strip()] = value
    return values


def detect(runner, os_release_path="/etc/os-release"):
    try:
        with open(os_release_path, encoding="utf-8") as fh:
            values = parse_os_release(fh.read())
    except OSError:
        values = {}
    res = runner.run([R.DPKG, "--print-architecture"])
    arch = res.stdout.strip() if res.ok else "unknown"
    return PlatformInfo(
        distro=values.get("ID", "unknown"),
        version_id=values.get("VERSION_ID", ""),
        codename=values.get("VERSION_CODENAME", ""),
        arch=arch,
        pretty=values.get("PRETTY_NAME", "unknown system"),
    )
