"""APT interfaces: candidate/repository information, holds, upgrade
simulation, and the commands wardctl runs.

Repository availability is derived from `apt-cache policy` version tables:
a version counts as repository-provided only if it is listed with a source
other than /var/lib/dpkg/status.
"""

import re
from dataclasses import dataclass, field

from wardctl import runner as R
from wardctl.errors import WardctlError

STATUS_FILE = "/var/lib/dpkg/status"
LOCK_TIMEOUT = 120  # seconds apt-get waits for the dpkg frontend lock

# Classification of an installed package against configured repositories.
NOT_INSTALLED = "not-installed"            # not installed; repository may offer it
UNAVAILABLE = "unavailable"                # not installed and no repository offers it
INSTALLED_ONLY = "installed-only"          # installed; no enabled repository supplies it
CURRENT = "current"                        # installed version == repository candidate
UPGRADABLE = "upgradable"                  # repository candidate is newer
INSTALLED_NEWER = "installed-newer"        # installed version newer than any repository version


@dataclass
class Source:
    priority: int
    description: str

    @property
    def is_status(self):
        return self.description.strip() == STATUS_FILE


@dataclass
class VersionEntry:
    version: str
    priority: int
    installed_marker: bool
    sources: list = field(default_factory=list)

    @property
    def from_repository(self):
        return any(not s.is_status for s in self.sources)


@dataclass
class Policy:
    name: str
    installed: str = None
    candidate: str = None
    versions: list = field(default_factory=list)

    def repository_versions(self):
        return [v for v in self.versions if v.from_repository]

    def repository_sources(self):
        return [s for v in self.versions for s in v.sources if not s.is_status]


_PKG_LINE = re.compile(r"^(\S+):$")
# " *** VERSION PRIO" marks the installed version; others are "     VERSION PRIO".
_VER_LINE = re.compile(r"^ (\*\*\*| {3}) (\S+) (-?\d+)$")
_SRC_LINE = re.compile(r"^ {8}(-?\d+) (.+)$")


def parse_policy(text):
    """Parse `apt-cache policy PKG...` output (LC_ALL=C) into Policy objects."""
    policies = {}
    cur = None
    ver = None
    for line in text.splitlines():
        m = _PKG_LINE.match(line)
        if m and not line.startswith(" "):
            name = m.group(1)
            cur = Policy(name.split(":")[0])
            policies[cur.name] = cur
            ver = None
            continue
        if cur is None:
            continue
        s = line.strip()
        if s.startswith("Installed:"):
            val = s.split(":", 1)[1].strip()
            cur.installed = None if val == "(none)" else val
        elif s.startswith("Candidate:"):
            val = s.split(":", 1)[1].strip()
            cur.candidate = None if val == "(none)" else val
        else:
            vm = _VER_LINE.match(line)
            if vm:
                ver = VersionEntry(vm.group(2), int(vm.group(3)), vm.group(1) == "***")
                cur.versions.append(ver)
                continue
            sm = _SRC_LINE.match(line)
            if sm and ver is not None:
                ver.sources.append(Source(int(sm.group(1)), sm.group(2).strip()))
    return policies


def parse_origins(text):
    """Parse bare `apt-cache policy` output into {source description: origin}."""
    origins = {}
    desc = None
    for line in text.splitlines():
        m = re.match(r"^ *(-?\d+) (\S.*)$", line)
        if m and not line.strip().startswith(("release", "origin")):
            desc = m.group(2).strip()
            origins.setdefault(desc, "")
            continue
        s = line.strip()
        if desc and s.startswith("release "):
            for item in s[len("release "):].split(","):
                key, _, val = item.partition("=")
                if key == "o":
                    origins[desc] = val
    return origins


def query_policies(runner, packages, chunk=400):
    result = {}
    packages = sorted(set(packages))
    for i in range(0, len(packages), chunk):
        res = runner.run([R.APT_CACHE, "policy", "--", *packages[i:i + chunk]])
        if not res.ok:
            raise WardctlError(f"apt-cache policy failed: {res.stderr.strip()}")
        result.update(parse_policy(res.stdout))
    return result


def query_origins(runner):
    res = runner.run([R.APT_CACHE, "policy"])
    return parse_origins(res.stdout) if res.ok else {}


def classify(installed_version, policy, comparer):
    """Classify a package. Never treats the dpkg status entry as a repository."""
    repo_versions = [v.version for v in policy.repository_versions()] if policy else []
    if installed_version is None:
        return (NOT_INSTALLED, policy.candidate) if repo_versions and policy.candidate else (UNAVAILABLE, None)
    if not repo_versions:
        return INSTALLED_ONLY, None
    candidate = policy.candidate
    if candidate is None or candidate not in repo_versions:
        # Candidate is the status entry (e.g. pinned away); use the newest repo version for reporting.
        candidate = comparer.newest(repo_versions)
    rel = comparer.compare(candidate, installed_version)
    if rel > 0:
        return UPGRADABLE, candidate
    if rel == 0:
        return CURRENT, candidate
    newest_repo = comparer.newest(repo_versions)
    if comparer.compare(newest_repo, installed_version) < 0:
        return INSTALLED_NEWER, newest_repo
    return CURRENT, candidate


def held_packages(runner):
    res = runner.run([R.APT_MARK, "showhold"])
    return set(res.stdout.split()) if res.ok else set()


@dataclass
class UpgradePlan:
    upgrades: list = field(default_factory=list)      # (pkg, old, new)
    installs: list = field(default_factory=list)      # (pkg, new)
    removals: list = field(default_factory=list)
    kept_back: list = field(default_factory=list)
    output: str = ""


_INST = re.compile(r"^Inst (\S+) (?:\[(\S+)\] )?\((\S+)")
_REMV = re.compile(r"^Remv (\S+)")
# apt < 3: "The following packages have been kept back:"; apt 3: "Not upgrading:"
_KEPT_HEADER = re.compile(r"^(The following packages? (?:have|has) been kept back|Not upgrading):?\s*$")


def parse_simulation(text):
    plan = UpgradePlan(output=text)
    kept = False
    for line in text.splitlines():
        m = _INST.match(line)
        if m:
            if m.group(2):
                plan.upgrades.append((m.group(1), m.group(2), m.group(3)))
            else:
                plan.installs.append((m.group(1), m.group(3)))
            kept = False
            continue
        m = _REMV.match(line)
        if m:
            plan.removals.append(m.group(1))
            continue
        if _KEPT_HEADER.match(line):
            kept = True
            continue
        if kept:
            if line.startswith("  "):
                plan.kept_back.extend(line.split())
            else:
                kept = False
    return plan


def lock_error(text):
    return bool(re.search(r"Could not get lock|Unable to acquire the dpkg frontend lock|"
                          r"Unable to lock directory", text))


class Apt:
    def __init__(self, runner, yes=False, conffile_policy="keep-old"):
        self.runner = runner
        self.yes = yes
        self.conffile_policy = conffile_policy

    def _common(self):
        args = ["-o", f"DPkg::Lock::Timeout={LOCK_TIMEOUT}"]
        if self.yes:
            new = "--force-confnew" if self.conffile_policy == "use-new" else "--force-confold"
            args += ["-y", "-o", "Dpkg::Options::=--force-confdef", "-o", f"Dpkg::Options::={new}"]
        return args

    def _env(self):
        extra = {}
        if self.yes:
            extra = {"DEBIAN_FRONTEND": "noninteractive", "NEEDRESTART_MODE": "l"}
        return R.base_env(extra)

    def refresh_argv(self):
        return [R.APT_GET, "update", "--error-on=any"]

    def refresh(self):
        return self.runner.run(self.refresh_argv(), interactive=True, env=self._env())

    def simulate(self, action="upgrade", packages=()):
        argv = [R.APT_GET, "-s", "-o", "Debug::NoLocking=1", action]
        if packages:
            argv += ["--", *packages]
        res = self.runner.run(argv)
        if not res.ok:
            raise WardctlError(f"apt-get simulation failed: {(res.stderr or res.stdout).strip()}")
        return parse_simulation(res.stdout)

    def upgrade_argv(self, action="upgrade"):
        return [R.APT_GET, *self._common(), action]

    def upgrade(self, action="upgrade"):
        return self.runner.run(self.upgrade_argv(action), interactive=True, env=self._env())

    def install_argv(self, targets, only_upgrade=False, allow_held=False):
        argv = [R.APT_GET, *self._common(), "install"]
        if only_upgrade:
            argv.append("--only-upgrade")
        if allow_held:
            argv.append("--allow-change-held-packages")
        return argv + ["--", *targets]

    def install(self, targets, only_upgrade=False, allow_held=False):
        return self.runner.run(self.install_argv(targets, only_upgrade, allow_held),
                               interactive=True, env=self._env())
