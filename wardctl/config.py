"""Versioned per-user configuration (~/.wardctl/config.json) and state.

config.json  - what the user wants tracked and how (user-editable, validated)
state.json   - observations: discovery results, last check results (regenerable)
cache/       - HTTP validator cache and staging area for downloads
logs/        - run log

Configuration never contains commands, hooks, plugins or executable paths;
every executable wardctl runs is a fixed absolute path in runner.py.
"""

import contextlib
import copy
import datetime
import json
import os
import re

from wardctl import fsutil
from wardctl.errors import ConfigError
from wardctl.privilege import as_user

SCHEMA_VERSION = 1

KINDS = ("deb", "flatpak", "standalone", "run-installer")
RESOLVERS = ("apt", "direct-deb", "github-release", "vendor-json", "html-link", "none")
POLICIES = ("prefer-apt", "apt-only", "direct-only", "check-only")
VERIFICATION = ("verified", "user-supplied", "unverified", "pending", "unsupported")
REGISTERED_BY = ("catalog", "user", "discovery")
CONFFILE_POLICIES = ("keep-old", "use-new")

ID_RE = re.compile(r"^[a-z0-9][a-z0-9.+-]{0,62}$")
PKG_RE = re.compile(r"^[a-z0-9][a-z0-9.+-]+$")
ARCH_RE = re.compile(r"^[a-z0-9-]{2,20}$")
HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")
FLATPAK_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*(\.[A-Za-z0-9_-]+){2,}$")
GITHUB_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
KEYRINGS = ("veracrypt",)

DEFAULT_SETTINGS = {
    "conffile_policy": "keep-old",
    "max_download_mb": 1024,
    "min_rollout": 1.0,
}

APP_KEYS = {"id", "display_name", "kind", "packages", "flatpak", "standalone", "source",
            "architectures", "update_policy", "allow_held_update", "verification",
            "provenance", "identity", "added_at", "updated_at", "notes"}


def today():
    return datetime.date.today().isoformat()


def now():
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()


def new_config():
    return {"schema_version": SCHEMA_VERSION, "settings": dict(DEFAULT_SETTINGS), "apps": {}}


# ---------------------------------------------------------------- validation

def _err(path, msg):
    raise ConfigError(f"config: {path}: {msg}",
                      hint="Fix the file by hand (it was not modified), or run `wardctl doctor`.")


def _https(path, url):
    if not isinstance(url, str) or not url.startswith("https://") or "@" in url.split("/")[2]:
        _err(path, f"must be an https:// URL without credentials, got {url!r}")


def validate_source(path, src):
    if not isinstance(src, dict):
        _err(path, "must be an object")
    resolver = src.get("resolver")
    if resolver not in RESOLVERS:
        _err(path + ".resolver", f"must be one of {', '.join(RESOLVERS)}")
    hosts = src.get("approved_hosts", [])
    if not isinstance(hosts, list) or not all(isinstance(h, str) and HOST_RE.match(h) for h in hosts):
        _err(path + ".approved_hosts", "must be a list of lowercase host names")
    for key in ("url", "page_url", "homepage"):
        if key in src and src[key] is not None:
            _https(f"{path}.{key}", src[key])
    if resolver == "direct-deb":
        if "url" not in src:
            _err(path, "direct-deb needs url")
        if not isinstance(src.get("pinned", False), bool):
            _err(path + ".pinned", "must be true or false")
    elif resolver == "github-release":
        if not GITHUB_REPO_RE.match(str(src.get("repo", ""))):
            _err(path + ".repo", "must be OWNER/REPO")
        pattern = src.get("asset_pattern")
        if not isinstance(pattern, str):
            _err(path + ".asset_pattern", "required")
        try:
            re.compile(pattern.replace("{arch}", "amd64").replace("{debian_major}", "13"))
        except re.error as exc:
            _err(path + ".asset_pattern", f"invalid regular expression: {exc}")
        sig = src.get("signature")
        if sig is not None:
            if not isinstance(sig, dict) or sig.get("keyring") not in KEYRINGS or \
                    not re.match(r"^\.[a-z0-9]{2,8}$", str(sig.get("suffix", ""))):
                _err(path + ".signature", f"needs suffix like '.sig' and a built-in keyring ({', '.join(KEYRINGS)})")
    elif resolver == "vendor-json":
        if src.get("format") != "proton-version-json":
            _err(path + ".format", "the only supported vendor JSON format is 'proton-version-json'")
        if "url" not in src:
            _err(path, "vendor-json needs url")
    elif resolver == "html-link":
        if "page_url" not in src:
            _err(path, "html-link needs page_url")
        try:
            re.compile(str(src.get("link_pattern")))
        except re.error as exc:
            _err(path + ".link_pattern", f"invalid regular expression: {exc}")
        if not src.get("link_pattern"):
            _err(path + ".link_pattern", "required")
    if resolver in ("direct-deb", "github-release", "vendor-json", "html-link") and not hosts:
        _err(path + ".approved_hosts", "at least one approved download host is required")


def validate_app(app_id, app):
    p = f"apps.{app_id}"
    if not isinstance(app, dict):
        _err(p, "must be an object")
    unknown = set(app) - APP_KEYS
    if unknown:
        _err(p, f"unknown keys: {', '.join(sorted(unknown))}")
    if not ID_RE.match(app_id) or app.get("id") != app_id:
        _err(p + ".id", "must match the key and be lowercase letters, digits, '.', '+', '-'")
    if not isinstance(app.get("display_name"), str) or not 0 < len(app["display_name"]) <= 100:
        _err(p + ".display_name", "required string (max 100 characters)")
    kind = app.get("kind")
    if kind not in KINDS:
        _err(p + ".kind", f"must be one of {', '.join(KINDS)}")
    pkgs = app.get("packages", [])
    if not isinstance(pkgs, list) or not all(isinstance(x, str) and PKG_RE.match(x) for x in pkgs):
        _err(p + ".packages", "must be a list of Debian package names")
    if kind == "deb" and not pkgs:
        _err(p + ".packages", "a deb application needs at least one package")
    if kind == "flatpak":
        fp = app.get("flatpak")
        if not isinstance(fp, dict) or not FLATPAK_RE.match(str(fp.get("app_id", ""))) or \
                fp.get("installation") not in ("user", "system"):
            _err(p + ".flatpak", "needs app_id and installation ('user' or 'system')")
    validate_source(p + ".source", app.get("source", {"resolver": "none"}))
    archs = app.get("architectures", [])
    if not isinstance(archs, list) or not all(isinstance(a, str) and ARCH_RE.match(a) for a in archs):
        _err(p + ".architectures", "must be a list of dpkg architecture names")
    if app.get("update_policy", "prefer-apt") not in POLICIES:
        _err(p + ".update_policy", f"must be one of {', '.join(POLICIES)}")
    if not isinstance(app.get("allow_held_update", False), bool):
        _err(p + ".allow_held_update", "must be true or false")
    ver = app.get("verification", {})
    if not isinstance(ver, dict) or ver.get("status", "unverified") not in VERIFICATION:
        _err(p + ".verification.status", f"must be one of {', '.join(VERIFICATION)}")
    prov = app.get("provenance", {})
    if not isinstance(prov, dict) or prov.get("registered_by", "user") not in REGISTERED_BY:
        _err(p + ".provenance.registered_by", f"must be one of {', '.join(REGISTERED_BY)}")
    ident = app.get("identity")
    if ident is not None:
        if not isinstance(ident, dict) or not PKG_RE.match(str(ident.get("package", ""))) or \
                not ARCH_RE.match(str(ident.get("architecture", ""))):
            _err(p + ".identity", "needs package and architecture")


def validate(cfg):
    if not isinstance(cfg, dict):
        _err("(top level)", "must be a JSON object")
    if cfg.get("schema_version") != SCHEMA_VERSION:
        _err("schema_version", f"expected {SCHEMA_VERSION}")
    settings = cfg.get("settings", {})
    if not isinstance(settings, dict):
        _err("settings", "must be an object")
    unknown = set(settings) - set(DEFAULT_SETTINGS)
    if unknown:
        _err("settings", f"unknown keys: {', '.join(sorted(unknown))}")
    if settings.get("conffile_policy", "keep-old") not in CONFFILE_POLICIES:
        _err("settings.conffile_policy", f"must be one of {', '.join(CONFFILE_POLICIES)}")
    mb = settings.get("max_download_mb", 1024)
    if not isinstance(mb, int) or isinstance(mb, bool) or not 1 <= mb <= 8192:
        _err("settings.max_download_mb", "must be an integer between 1 and 8192")
    roll = settings.get("min_rollout", 1.0)
    if not isinstance(roll, (int, float)) or isinstance(roll, bool) or not 0 <= roll <= 1:
        _err("settings.min_rollout", "must be a number between 0 and 1")
    apps = cfg.get("apps")
    if not isinstance(apps, dict):
        _err("apps", "must be an object keyed by application id")
    for app_id, app in apps.items():
        validate_app(app_id, app)
    return cfg


# ----------------------------------------------------------------- migration

def _migrate_0_to_1(cfg):
    """Pre-release layout: {"apps": [ {...}, ... ]} without schema_version."""
    apps = {}
    for item in cfg.get("apps", []):
        if not isinstance(item, dict) or "id" not in item:
            _err("apps", "legacy entries need an id")
        item = dict(item)
        item.setdefault("display_name", item["id"])
        item.setdefault("kind", "deb")
        item.setdefault("source", {"resolver": "none"})
        item.setdefault("provenance", {"registered_by": "user"})
        apps[item["id"]] = item
    return {"schema_version": 1, "settings": dict(DEFAULT_SETTINGS), "apps": apps}


MIGRATIONS = {0: _migrate_0_to_1}


def migrate(cfg):
    """Return (config, migrated?) at SCHEMA_VERSION."""
    if not isinstance(cfg, dict):
        _err("(top level)", "must be a JSON object")
    version = cfg.get("schema_version", 0)
    if not isinstance(version, int) or isinstance(version, bool):
        _err("schema_version", "must be an integer")
    if version > SCHEMA_VERSION:
        raise ConfigError(
            f"config schema version {version} is newer than this wardctl supports ({SCHEMA_VERSION})",
            hint="Upgrade wardctl; the file was left untouched.")
    migrated = False
    while version < SCHEMA_VERSION:
        step = MIGRATIONS.get(version)
        if step is None:
            _err("schema_version", f"no migration from version {version}")
        cfg = step(copy.deepcopy(cfg))
        version = cfg["schema_version"]
        migrated = True
    settings = dict(DEFAULT_SETTINGS)
    settings.update(cfg.get("settings", {}))
    cfg["settings"] = settings
    return cfg, migrated


# --------------------------------------------------------------------- store

class UserPaths:
    def __init__(self, home):
        self.home = home
        self.root = os.path.join(home, ".wardctl")
        self.config = os.path.join(self.root, "config.json")
        self.state = os.path.join(self.root, "state.json")
        self.cache = os.path.join(self.root, "cache")
        self.staging = os.path.join(self.cache, "staging")
        self.logs = os.path.join(self.root, "logs")
        self.log = os.path.join(self.logs, "wardctl.log")
        self.lock = os.path.join(self.root, "lock")


class Store:
    """User-owned files. Every filesystem access runs with the user's
    credentials. In read-only mode (dry-run) writes are a programming error."""

    def __init__(self, identity, read_only=False):
        self.identity = identity
        self.paths = UserPaths(identity.home)
        self.read_only = read_only

    def _guard(self):
        if self.read_only:
            raise RuntimeError("attempted to write persistent state in read-only (dry-run) mode")

    def exists(self):
        with as_user(self.identity):
            return os.path.lexists(self.paths.config)

    def ensure_dirs(self):
        self._guard()
        uid = self.identity.uid
        with as_user(self.identity):
            fsutil.check_home(self.paths.home, uid)
            for d in (self.paths.root, self.paths.cache, self.paths.staging, self.paths.logs):
                fsutil.ensure_private_dir(d, uid)

    def validate_dirs(self):
        """Read-only validation of existing directories."""
        uid = self.identity.uid
        with as_user(self.identity):
            fsutil.check_home(self.paths.home, uid)
            for d in (self.paths.root, self.paths.cache, self.paths.staging, self.paths.logs):
                if os.path.lexists(d):
                    fsutil.ensure_private_dir(d, uid)

    def _read_json(self, path):
        with as_user(self.identity):
            if os.path.lexists(self.paths.root):
                fsutil.ensure_private_dir(self.paths.root, self.identity.uid)
            raw = fsutil.read_private(path, self.identity.uid)
        if raw is None:
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            where = f" (line {exc.lineno}, column {exc.colno})" if isinstance(exc, json.JSONDecodeError) else ""
            raise ConfigError(f"{path} is not valid JSON{where}: {exc}",
                              hint="Repair the file by hand; wardctl left it untouched. "
                                   "`wardctl doctor` shows details.")

    def load_config(self, allow_missing=True):
        cfg = self._read_json(self.paths.config)
        if cfg is None:
            if not allow_missing:
                raise ConfigError(f"{self.paths.config} does not exist", hint="Run `wardctl init`.")
            return new_config(), False
        cfg, migrated = migrate(cfg)
        validate(cfg)
        return cfg, migrated

    def backup_config(self, suffix):
        self._guard()
        with as_user(self.identity):
            raw = fsutil.read_private(self.paths.config, self.identity.uid)
            if raw is not None:
                fsutil.atomic_write(self.paths.config + suffix, raw)

    def save_config(self, cfg):
        self._guard()
        validate(cfg)
        data = (json.dumps(cfg, indent=2, sort_keys=True) + "\n").encode()
        self.ensure_dirs()
        with as_user(self.identity):
            fsutil.atomic_write(self.paths.config, data)

    def load_state(self):
        try:
            state = self._read_json(self.paths.state)
        except ConfigError:
            # State is regenerable; preserve the damaged copy for inspection.
            if not self.read_only:
                with as_user(self.identity):
                    os.replace(self.paths.state, self.paths.state + ".corrupt")
            return {"schema_version": 1, "corrupt_state_recovered": True}
        if not isinstance(state, dict):
            return {"schema_version": 1}
        return state

    def save_state(self, state):
        self._guard()
        state["schema_version"] = 1
        data = (json.dumps(state, indent=2, sort_keys=True) + "\n").encode()
        self.ensure_dirs()
        with as_user(self.identity):
            fsutil.atomic_write(self.paths.state, data)

    def log(self, message):
        if self.read_only:
            return
        try:
            with as_user(self.identity):
                if os.path.isdir(self.paths.logs) and not os.path.islink(self.paths.logs):
                    fsutil.append_private(self.paths.log, self.identity.uid, f"{now()} {message}\n")
        except Exception:  # logging must never break a run
            pass

    @contextlib.contextmanager
    def user_lock(self):
        """Per-user application lock (flock on ~/.wardctl/lock)."""
        from wardctl.locks import FileLock
        self.ensure_dirs()
        lock = FileLock(self.paths.lock, self.identity.uid, "wardctl for this user")
        with as_user(self.identity):
            lock.acquire()
        try:
            yield lock
        finally:
            lock.release()
