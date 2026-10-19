"""Planning and executing checks, updates and installs."""

import json
import os
import re
import shutil
import stat
import sys
import tempfile
from dataclasses import dataclass, field

from wardctl import apt, catalog, config, debpkg, flatpak, locks, verify, worker
from wardctl.errors import (EXIT_FATAL, EXIT_OK, EXIT_PARTIAL, EXIT_UPDATES, LockBusy,
                              WardctlError, ResolveError, UserAbort, VerificationError)
from wardctl.netfetch import redact
from wardctl.privilege import as_user, package_parent, user_env, user_process_kwargs

SYSTEM_CACHE = "/var/cache/wardctl"

# Application states
UP_TO_DATE = "up-to-date"
UPDATE_AVAILABLE = "update-available"
INSTALLED_NEWER = "installed-newer"
HELD = "held"
NOT_INSTALLED = "not-installed"
UNRESOLVED = "unresolved"
UNSUPPORTED = "unsupported"
UNCHECKED = "unchecked"
ERROR = "error"


@dataclass
class Context:
    runner: object
    identity: object
    platform: object
    store: object
    http: object
    out: object
    yes: bool = False
    dry_run: bool = False
    interactive: bool = True
    system_cache: str = SYSTEM_CACHE
    system_lock_path: str = locks.SYSTEM_LOCK
    apt_lock_probe: object = staticmethod(locks.apt_lock_holder)
    confirm_fn: object = None


@dataclass
class AppStatus:
    app_id: str
    name: str
    kind: str
    manager: str = "none"           # apt | direct | flatpak | none
    state: str = UNCHECKED
    installed: str = None
    available: str = None
    detail: str = ""
    notes: list = field(default_factory=list)
    release: dict = None
    control: dict = None
    held: bool = False

    def to_dict(self):
        d = dict(self.__dict__)
        d.pop("release", None)
        d.pop("control", None)
        return d


@dataclass
class Snapshot:
    installed: dict
    policies: dict
    held: set
    comparer: object
    flatpaks: dict = None


@dataclass
class Summary:
    steps: list = field(default_factory=list)
    fatal: bool = False

    def add(self, name, status, detail=""):
        self.steps.append((name, status, detail))

    @property
    def failed(self):
        return [s for s in self.steps if s[1] == "failed"]

    def exit_code(self):
        if self.fatal:
            return EXIT_FATAL
        return EXIT_PARTIAL if self.failed else EXIT_OK


# ----------------------------------------------------------------- helpers

def load_snapshot(ctx, apps, with_flatpak=True):
    comparer = debpkg.VersionComparer(ctx.runner)
    pkgs = sorted({p for a in apps for p in a.get("packages", [])})
    installed = debpkg.query_installed(ctx.runner, pkgs) if pkgs else {}
    policies = apt.query_policies(ctx.runner, pkgs) if pkgs else {}
    held = {n for n, p in installed.items() if p.held} | (apt.held_packages(ctx.runner) if pkgs else set())
    fps = None
    if with_flatpak and any(a.get("kind") == "flatpak" for a in apps):
        fps = flatpak.list_installed(ctx.runner, ctx.identity)
    return Snapshot(installed, policies, held, comparer, fps)


WORKER_BOOT = ("import sys; sys.path.insert(0, {path!r}); "
               "from wardctl.worker import main; sys.exit(main())")


def call_worker(ctx, request):
    """Run untrusted-network work as the invoking user."""
    if ctx.identity.drops_privileges:
        argv = [sys.executable, "-I", "-c", WORKER_BOOT.format(path=package_parent())]
        res = ctx.runner.run(argv, input=json.dumps(request), env=user_env(ctx.identity),
                             user_kwargs=user_process_kwargs(ctx.identity), cwd="/")
        try:
            out = json.loads(res.stdout)
        except (json.JSONDecodeError, TypeError):
            raise WardctlError(f"unprivileged helper failed: {(res.stderr or '').strip()[-400:]}")
    else:
        try:
            out = worker.handle(request, runner=ctx.runner, http=ctx.http)
        except WardctlError as exc:
            out = {"ok": False, "error": str(exc), "hint": exc.hint, "type": type(exc).__name__}
    if not out.get("ok"):
        cls = {"VerificationError": VerificationError}.get(out.get("type"), ResolveError)
        raise cls(out.get("error", "unknown error"), out.get("hint"))
    return out


def prepare_request(ctx, cfg, app, mode):
    staging = None
    if mode == "download":
        ctx.store.ensure_dirs()
        staging = ctx.store.paths.staging
    return {"task": "prepare", "app": app, "mode": mode, "arch": ctx.platform.arch,
            "debian_major": ctx.platform.debian_major, "staging_dir": staging,
            "min_rollout": cfg["settings"]["min_rollout"],
            "max_bytes": cfg["settings"]["max_download_mb"] * 1024 * 1024}


def _has_direct_source(app):
    return app.get("source", {}).get("resolver") in ("direct-deb", "github-release", "vendor-json", "html-link")


# --------------------------------------------------------------- evaluation

def evaluate(ctx, cfg, app, snap, resolve=False, flatpak_updates=None):
    st = AppStatus(app["id"], app["display_name"], app["kind"])
    policy = app.get("update_policy", "prefer-apt")
    ver = app.get("verification", {})

    if app["kind"] in ("standalone", "run-installer"):
        probes = (app.get("standalone") or {}).get("probe_paths", [])
        st.installed = "detected" if catalog.probe_exists(probes) else None
        st.state = UNSUPPORTED
        st.detail = ver.get("method", "no verified adapter for this installer type")
        return st

    if app["kind"] == "flatpak":
        fp = app["flatpak"]
        st.manager = "flatpak"
        installs = snap.flatpaks or {}
        key = (fp["app_id"], fp["installation"])
        if key not in installs:
            st.state = NOT_INSTALLED
            st.detail = f"Flatpak {fp['app_id']} ({fp['installation']}) is not installed"
            return st
        st.installed = installs[key] or "installed"
        if not resolve:
            st.detail = f"{fp['installation']} Flatpak; run `wardctl check` to contact the remote"
            return st
        pending, err = (flatpak_updates or {}).get(fp["installation"], (None, "not checked"))
        if pending is None:
            st.state = ERROR
            st.detail = f"flatpak remote-ls failed: {err}"
        elif fp["app_id"] in pending:
            st.state = UPDATE_AVAILABLE
            st.detail = f"{fp['installation']} Flatpak update available"
        else:
            st.state = UP_TO_DATE
            st.detail = f"{fp['installation']} Flatpak"
        return st

    # --- deb
    pkgs = app["packages"]
    main = pkgs[0]
    inst = snap.installed.get(main)
    st.installed = inst.version if inst else None
    st.held = any(p in snap.held for p in pkgs if p in snap.installed)
    if inst and app.get("architectures") and inst.arch not in app["architectures"] + ["all"]:
        st.notes.append(f"installed architecture {inst.arch} is not in the registered list")

    cls, cand = apt.classify(st.installed, snap.policies.get(main), snap.comparer)
    extra_upgradable = []
    for p in pkgs[1:]:
        ip = snap.installed.get(p)
        if ip:
            c, v = apt.classify(ip.version, snap.policies.get(p), snap.comparer)
            if c == apt.UPGRADABLE:
                extra_upgradable.append(f"{p} {ip.version} -> {v}")
    repo = cls in (apt.NOT_INSTALLED, apt.CURRENT, apt.UPGRADABLE)

    if policy == "direct-only" and repo and _has_direct_source(app):
        st.notes.append(f"source-policy override (direct-only): APT repository version {cand} is ignored; "
                        "apt-get upgrade may still replace this package if the repository version is newer")
        repo = False

    if repo:
        st.manager = "apt"
        st.available = cand
        if cls == apt.NOT_INSTALLED:
            st.state, st.detail = NOT_INSTALLED, "available from an enabled APT repository"
        elif cls == apt.UPGRADABLE or extra_upgradable:
            st.state = HELD if st.held else UPDATE_AVAILABLE
            st.detail = "APT repository update" + (" (package is held)" if st.held else "")
            if extra_upgradable:
                st.notes.append("also upgradable: " + ", ".join(extra_upgradable))
        else:
            st.state, st.detail = UP_TO_DATE, "managed by APT"
        return st

    if cls == apt.INSTALLED_NEWER:
        st.notes.append(f"installed {st.installed} is newer than the repository version {cand}; "
                        "APT will not downgrade it")
    if policy == "apt-only" or not _has_direct_source(app):
        st.manager = "apt" if cls == apt.INSTALLED_NEWER else "none"
        if cls == apt.INSTALLED_NEWER:
            st.state, st.available = INSTALLED_NEWER, cand
            st.detail = "installed version is newer than any repository version"
        elif inst is None:
            st.state = NOT_INSTALLED if cls != apt.UNAVAILABLE else UNRESOLVED
            st.detail = ("no enabled APT repository provides it"
                         + (" (vendor repository not configured; wardctl does not add repositories)"
                            if catalog.CATALOG.get(app["id"], {}).get("vendor_repository") else ""))
        else:
            st.state = UNRESOLVED
            st.detail = ("installed, but no enabled APT repository supplies it and no verified update source "
                         "is configured. Where it was originally downloaded from is unknown (dpkg does not "
                         f"record it). Register a source: wardctl add {app['id']} --url URL")
        return st

    st.manager = "direct"
    if not resolve:
        st.detail = f"direct source ({app['source']['resolver']}); run `wardctl check` to query it"
        return st
    try:
        res = call_worker(ctx, prepare_request(ctx, cfg, app, "metadata"))
    except WardctlError as exc:
        st.state, st.detail = ERROR, str(exc) + (f" ({exc.hint})" if exc.hint else "")
        return st
    st.release, st.control = res["release"], res.get("control")
    st.notes.extend(st.release.get("notes", []))
    candidate = (st.control or {}).get("version") or st.release.get("version")
    st.available = candidate
    if inst is None:
        st.state, st.detail = NOT_INSTALLED, f"available from {app['source']['resolver']} source"
        return st
    rel = snap.comparer.compare(candidate, st.installed)
    if rel > 0:
        if st.held and not app.get("allow_held_update"):
            st.state, st.detail = HELD, "newer release available but the package is held"
        else:
            st.state, st.detail = UPDATE_AVAILABLE, f"newer release from {app['source']['resolver']} source"
    elif rel == 0:
        st.state, st.detail = UP_TO_DATE, f"matches the latest {app['source']['resolver']} release"
    else:
        st.state, st.detail = INSTALLED_NEWER, "installed version is newer than the published release"
    if policy == "check-only" and st.state == UPDATE_AVAILABLE:
        st.notes.append("update policy is check-only; wardctl will not install it")
    return st


def tracked_apps(cfg, app_id=None):
    apps = cfg["apps"]
    if app_id is None:
        return list(apps.values())
    if app_id not in apps:
        raise WardctlError(f"{app_id!r} is not tracked",
                            hint="See `wardctl list`; register with `wardctl add`.")
    return [apps[app_id]]


def flatpak_pending(ctx, apps):
    result = {}
    for inst in {a["flatpak"]["installation"] for a in apps if a.get("kind") == "flatpak"}:
        result[inst] = flatpak.pending_updates(ctx.runner, ctx.identity, inst)
    return result


# ------------------------------------------------------------------ output

STATE_LABEL = {UP_TO_DATE: "up to date", UPDATE_AVAILABLE: "UPDATE AVAILABLE", INSTALLED_NEWER: "installed newer",
               HELD: "held", NOT_INSTALLED: "not installed", UNRESOLVED: "unresolved source",
               UNSUPPORTED: "unsupported", UNCHECKED: "not checked", ERROR: "ERROR"}


def print_statuses(out, statuses):
    rows = [(s.app_id, s.manager, STATE_LABEL.get(s.state, s.state), s.installed or "-", s.available or "-")
            for s in statuses]
    out.table(("APP", "VIA", "STATE", "INSTALLED", "AVAILABLE"), rows)
    for s in statuses:
        if s.state in (ERROR, UNRESOLVED, UNSUPPORTED, HELD) or s.notes:
            out.info(f"  {s.app_id}: {s.detail}")
            for n in s.notes:
                out.info(f"  {s.app_id}: note: {n}")


# ------------------------------------------------------------------- check

def check(ctx, cfg, app_id=None):
    apps = tracked_apps(cfg, app_id)
    snap = load_snapshot(ctx, apps)
    fp = flatpak_pending(ctx, apps)
    statuses = [evaluate(ctx, cfg, a, snap, resolve=True, flatpak_updates=fp) for a in apps]
    system = None
    if app_id is None:
        try:
            system = apt.Apt(ctx.runner).simulate("upgrade")
        except WardctlError as exc:
            ctx.out.warn(f"could not simulate apt-get upgrade: {exc}")
    return statuses, system


def check_exit(statuses, system):
    if any(s.state == ERROR for s in statuses):
        return EXIT_PARTIAL
    if any(s.state == UPDATE_AVAILABLE for s in statuses) or (system and system.upgrades):
        return EXIT_UPDATES
    return EXIT_OK


# ----------------------------------------------------------------- confirm

def confirm(ctx, question):
    if ctx.yes:
        return True
    if ctx.confirm_fn:
        return ctx.confirm_fn(question)
    if not ctx.interactive:
        raise UserAbort("confirmation needed but stdin is not a terminal",
                        hint="Re-run with --yes for noninteractive operation.")
    answer = input(f"{question} [y/N] ").strip().lower()
    return answer in ("y", "yes")


# ---------------------------------------------------------- direct install

def _ensure_root_dir(path, mode):
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        os.mkdir(path, mode)
        st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() \
            or st.st_mode & 0o022:
        raise VerificationError(f"{path} is not a safe root-owned directory")
    os.chmod(path, mode)


def _copy_from_user(ctx, src, dst):
    """Open the user's staged file with the user's credentials (refusing
    symlinks), then copy it into a root-owned file. Returns (sha256, sha512)."""
    with as_user(ctx.identity):
        fd = os.open(src, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    import hashlib
    h256, h512 = hashlib.sha256(), hashlib.sha512()
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != ctx.identity.uid:
            raise VerificationError(f"staged file {src} is not a regular file owned by {ctx.identity.name}")
        out_fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
        with os.fdopen(out_fd, "wb") as out:
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                h256.update(chunk)
                h512.update(chunk)
                out.write(chunk)
            os.fchmod(out.fileno(), 0o644)
    finally:
        os.close(fd)
    return h256.hexdigest(), h512.hexdigest()


def promote(ctx, app, prep):
    """Copy a prepared artifact into a root-owned staging directory readable
    by APT's download sandbox, and re-verify it there as root."""
    art = prep["artifact"]
    release = prep["release"]
    _ensure_root_dir(ctx.system_cache, 0o755)
    staging_root = os.path.join(ctx.system_cache, "staging")
    _ensure_root_dir(staging_root, 0o755)
    workdir = tempfile.mkdtemp(prefix="deb-", dir=staging_root)
    os.chmod(workdir, 0o755)
    try:
        name = re.sub(r"[^a-z0-9.+-]", "_", prep["control"]["package"]) + ".deb"
        dst = os.path.join(workdir, name)
        sha256, sha512 = _copy_from_user(ctx, art["path"], dst)
        if sha256 != art["sha256"]:
            raise VerificationError("staged file changed after verification; refusing to install")
        verify.check_checksums(release.get("checksums") or {}, sha256, sha512)
        if art.get("sig_path"):
            sig_dst = dst + ".sig"
            _copy_from_user(ctx, art["sig_path"], sig_dst)
            verify.check_signature(ctx.runner, release["keyring"], sig_dst, dst)
        info = debpkg.inspect_deb(ctx.runner, dst)
        debpkg.check_identity(info, app, ctx.platform.arch)
        if info.version != prep["control"]["version"]:
            raise VerificationError("package version changed between preparation and installation")
        return workdir, dst, info
    except BaseException:
        shutil.rmtree(workdir, ignore_errors=True)
        raise


def cleanup_user_dir(ctx, path):
    if not path:
        return
    with as_user(ctx.identity):
        shutil.rmtree(path, ignore_errors=True)


def describe_release(release):
    parts = [release.get("label") or ""]
    if release.get("checksum_source"):
        parts.append(f"checksum: {release['checksum_source']}")
    if release.get("signature_url"):
        parts.append(f"OpenPGP signature checked with bundled '{release.get('keyring')}' key")
    if not release.get("checksums") and not release.get("signature_url"):
        parts.append("no published checksum or signature: authenticity rests on HTTPS to the official host")
    return "; ".join(p for p in parts if p)


def direct_install(ctx, cfg, app, status, held=False):
    """Download, verify and install one direct-source package through APT."""
    apt_ = apt.Apt(ctx.runner, ctx.yes, cfg["settings"]["conffile_policy"])
    if ctx.dry_run:
        rel = status.release or {}
        ctx.out.info(f"  would download {redact(rel.get('url', ''))} as {ctx.identity.name}, verify it "
                     f"({describe_release(rel)}), and run: apt-get install /var/cache/wardctl/staging/…/"
                     f"{app['packages'][0]}.deb")
        return "planned", "dry run"
    if not confirm(ctx, f"Install {app['display_name']} {status.available or ''} from its "
                        f"{app['source']['resolver']} source?"):
        return "skipped", "declined"
    prep = call_worker(ctx, prepare_request(ctx, cfg, app, "download"))
    user_dir = prep["artifact"]["dir"]
    root_dir = None
    try:
        root_dir, deb, info = promote(ctx, app, prep)
        if status.installed and debpkg.VersionComparer(ctx.runner).compare(info.version, status.installed) <= 0:
            return "skipped", f"downloaded {info.version} is not newer than installed {status.installed}"
        ctx.out.info(f"  verified {info.package} {info.version} ({info.arch}); {describe_release(prep['release'])}")
        res = apt_.install([deb], allow_held=held and app.get("allow_held_update", False))
        if not res.ok:
            return "failed", f"apt-get install exited {res.returncode}"
        now = debpkg.query_installed(ctx.runner, [info.package]).get(info.package)
        if not now or now.version != info.version:
            return "failed", f"apt-get finished but {info.package} is at {now.version if now else 'not installed'}"
        ident = app.setdefault("identity", {})
        if not ident:
            ident.update(package=info.package, architecture=info.arch, verified_on=config.today())
        return "ok", f"installed {info.version}"
    finally:
        if root_dir:
            shutil.rmtree(root_dir, ignore_errors=True)
        cleanup_user_dir(ctx, user_dir)


# ------------------------------------------------------------------ update

def preflight(ctx):
    ctx.platform.require_supported("Installing or updating software")
    if not ctx.identity.is_root_process:
        raise WardctlError("root privileges are required for this operation",
                            hint="Run with sudo (wardctl re-runs itself with sudo when installed system-wide).")
    if not ctx.yes and not ctx.interactive:
        raise UserAbort("stdin is not a terminal and --yes was not given",
                        hint="Use --yes for noninteractive runs (conffile policy: settings.conffile_policy).")
    holder = ctx.apt_lock_probe()
    if holder:
        path, pid = holder
        raise LockBusy(f"APT/dpkg is in use: {path} is locked by PID {pid} ({locks.process_name(pid)})",
                       hint="Let the other package operation finish, then retry. wardctl never removes "
                            "APT locks or stops package managers.")


def run_update(ctx, cfg, app_id=None, apt_only=False, apps_only=False, full_upgrade=False):
    summary = Summary()
    out = ctx.out
    apt_ = apt.Apt(ctx.runner, ctx.yes, cfg["settings"]["conffile_policy"])
    targets = tracked_apps(cfg, app_id) if not apt_only else []
    system_upgrade = app_id is None and not apps_only
    action = "full-upgrade" if full_upgrade else "upgrade"

    # 1. metadata refresh
    out.section("APT metadata refresh")
    if ctx.dry_run:
        out.info("would run: " + " ".join(apt_.refresh_argv()))
        out.info("(dry run: the plan below uses the metadata from the last refresh)")
        summary.add("apt-get update", "planned")
    else:
        res = apt_.refresh()
        if not res.ok:
            summary.add("apt-get update", "failed", f"exit {res.returncode}")
            summary.fatal = True
            out.error("APT metadata refresh failed; stopping before any upgrade or install.")
            return summary, []
        summary.add("apt-get update", "ok")

    # 2. system upgrade
    apt_failed = False
    if system_upgrade:
        out.section(f"System packages (apt-get {action})")
        try:
            plan = apt_.simulate(action)
        except WardctlError as exc:
            summary.add(f"apt-get {action}", "failed", str(exc))
            plan, apt_failed = None, True
        if plan is not None:
            held = sorted(apt.held_packages(ctx.runner))
            out.info(f"{len(plan.upgrades)} to upgrade, {len(plan.installs)} new, "
                     f"{len(plan.removals)} to remove, {len(plan.kept_back)} kept back")
            for pkg, old, new in plan.upgrades:
                out.info(f"  {pkg} {old} -> {new}")
            if plan.kept_back:
                out.info("  kept back (not forced): " + " ".join(plan.kept_back))
            if held:
                out.info("  held (respected): " + " ".join(held))
            if plan.removals and not full_upgrade:
                out.warn("apt-get upgrade unexpectedly plans removals: " + " ".join(plan.removals))
            if ctx.dry_run:
                summary.add(f"apt-get {action}", "planned", f"{len(plan.upgrades)} upgrades")
            elif not (plan.upgrades or plan.installs or plan.removals):
                summary.add(f"apt-get {action}", "ok", "nothing to upgrade")
            else:
                res = apt_.upgrade(action)
                if res.ok:
                    summary.add(f"apt-get {action}", "ok", f"{len(plan.upgrades)} upgraded")
                else:
                    apt_failed = True
                    summary.add(f"apt-get {action}", "failed", f"exit {res.returncode}")
            if plan.kept_back:
                summary.add("kept back", "info", " ".join(plan.kept_back))

    # 3. applications (state re-read from dpkg after APT ran)
    statuses = []
    if targets:
        out.section("Tracked applications")
        snap = load_snapshot(ctx, targets)
        fp = flatpak_pending(ctx, targets)
        for app in targets:
            st = evaluate(ctx, cfg, app, snap, resolve=True, flatpak_updates=fp)
            statuses.append(st)
            label = f"{app['id']}"
            if st.state == ERROR:
                summary.add(label, "failed", st.detail)
                continue
            if st.state == HELD:
                summary.add(label, "skipped", f"held ({st.available} available)")
                continue
            if st.state != UPDATE_AVAILABLE:
                if app_id and st.state == NOT_INSTALLED:
                    summary.add(label, "skipped", "not installed; use `wardctl install`")
                else:
                    summary.add(label, "nothing", STATE_LABEL.get(st.state, st.state))
                continue
            if app.get("update_policy") == "check-only":
                summary.add(label, "skipped", f"{st.available} available; policy is check-only")
                continue
            try:
                if st.manager == "apt":
                    if apt_failed:
                        summary.add(label, "skipped", "APT failed earlier; not bypassed with a download")
                    elif system_upgrade and ctx.dry_run:
                        summary.add(label, "planned", f"{st.installed} -> {st.available} in apt-get {action}")
                    elif system_upgrade:
                        summary.add(label, "skipped", "kept back by apt-get upgrade; not forced")
                    else:
                        pkgs = [p for p in app["packages"] if p in snap.installed]
                        if ctx.dry_run:
                            out.info(f"  would run: {' '.join(apt_.install_argv(pkgs, only_upgrade=True))}")
                            summary.add(label, "planned", f"{st.installed} -> {st.available} via APT")
                        else:
                            res = apt_.install(pkgs, only_upgrade=True)
                            summary.add(label, "ok" if res.ok else "failed",
                                        f"{st.installed} -> {st.available}" if res.ok else f"apt-get exit {res.returncode}")
                            apt_failed = apt_failed or not res.ok
                elif st.manager == "direct":
                    if apt_failed:
                        summary.add(label, "skipped", "APT failed earlier; skipping direct-source installs")
                        continue
                    out.info(f"{app['display_name']}: {st.installed} -> {st.available}")
                    status, detail = direct_install(ctx, cfg, app, st, held=st.held)
                    summary.add(label, status, detail)
                elif st.manager == "flatpak":
                    fpi = app["flatpak"]
                    if ctx.dry_run:
                        summary.add(label, "planned", f"flatpak update --{fpi['installation']} {fpi['app_id']}")
                    else:
                        res = flatpak.update(ctx.runner, ctx.identity, fpi["installation"], fpi["app_id"], ctx.yes)
                        summary.add(label, "ok" if res.ok else "failed",
                                    "updated" if res.ok else f"flatpak exit {res.returncode}")
            except (WardctlError, OSError) as exc:
                summary.add(label, "failed", str(exc))
    if debpkg.reboot_required():
        summary.add("reboot", "info", "the system reports a reboot is required (/run/reboot-required); "
                                      "wardctl never reboots automatically")
    return summary, statuses


def print_summary(out, summary):
    out.section("Summary")
    out.table(("STEP", "RESULT", "DETAIL"), [(n, s, d) for n, s, d in summary.steps])
    code = summary.exit_code()
    msg = {EXIT_OK: "completed successfully", EXIT_PARTIAL: "completed with failures",
           EXIT_FATAL: "stopped by a fatal error"}[code]
    out.info(f"\nResult: {msg} (exit {code})")


# ----------------------------------------------------------- registration

def register_from_url(ctx, cfg, url, app_id=None, name=None, package=None, asset_pattern=None,
                      allow_hosts=(), pinned=None):
    """Build (but do not save) an app record from a user-supplied URL, after
    verifying the package identity the URL serves."""
    page_app = catalog.match_page(url)
    if page_app:
        ctx.out.info(f"{url} is the official download page for {page_app}; using its maintained adapter.")
        return catalog.to_record(catalog.get(page_app), registered_by="user", today=config.today()), None
    req = {"task": "probe", "url": url, "arch": ctx.platform.arch, "debian_major": ctx.platform.debian_major,
           "allowed_hosts": list(allow_hosts), "asset_pattern": asset_pattern,
           "min_rollout": cfg["settings"]["min_rollout"]}
    res = call_worker(ctx, req)
    control = res["control"]
    if package and control["package"] != package:
        raise VerificationError(f"{url} serves package {control['package']!r}, not {package!r}")
    source = res["source"]
    user_supplied = ["source.url"]
    if source["resolver"] == "direct-deb":
        upstream = control["version"].split(":")[-1].split("-")[0]
        looks_pinned = bool(upstream) and upstream in url
        source["pinned"] = looks_pinned if pinned is None else pinned
        if pinned is not None:
            user_supplied.append("source.pinned")
        if source["pinned"]:
            ctx.out.warn("this URL serves one fixed release (pinned). wardctl will not discover newer "
                         "releases from it; prefer a vendor 'latest' endpoint, GitHub repository or manifest.")
    if asset_pattern:
        user_supplied.append("source.asset_pattern")
    if allow_hosts:
        user_supplied.append("source.approved_hosts")
    rid = app_id or control["package"]
    if not config.ID_RE.match(rid):
        raise WardctlError(f"invalid application id {rid!r}")
    rec = {
        "id": rid, "display_name": name or control["package"], "kind": "deb", "packages": [control["package"]],
        "source": source,
        "architectures": [] if control["arch"] == "all" else [control["arch"]],
        "update_policy": "prefer-apt", "allow_held_update": False,
        "identity": {"package": control["package"], "architecture": control["arch"],
                     "verified_on": config.today()},
        "verification": {"status": "user-supplied", "checked_on": config.today(),
                         "method": "source supplied by the user; package identity read from its control data "
                                   f"({control['package']} {control['version']} {control['arch']})"},
        "provenance": {"registered_by": "user", "user_supplied": user_supplied,
                       "inferred": ["identity (from package control data)"]
                       + ([] if name else ["display_name"]) + ([] if app_id else ["id"]),
                       "install_origin": "unknown"},
        "added_at": config.today(),
    }
    return rec, control


def run_install(ctx, cfg, app, snap):
    """Install a registered or catalog app on explicit request."""
    st = evaluate(ctx, cfg, app, snap, resolve=_has_direct_source(app))
    if st.installed and st.state in (UP_TO_DATE, INSTALLED_NEWER, UPDATE_AVAILABLE, HELD, UNCHECKED, UNRESOLVED):
        ctx.out.info(f"{app['display_name']} is already installed ({st.installed}); "
                     f"use `wardctl update {app['id']}` to update it.")
        return "nothing", "already installed"
    if app["kind"] == "flatpak":
        fp = app["flatpak"]
        raise WardctlError(f"wardctl does not install Flatpaks or add Flatpak remotes",
                            hint=f"Install it yourself, e.g.: flatpak install --{fp['installation']} {fp['app_id']}")
    if st.state == UNSUPPORTED:
        raise WardctlError(f"{app['display_name']}: {st.detail}")
    if st.state == ERROR:
        raise ResolveError(st.detail)
    if st.manager == "apt" and st.state == NOT_INSTALLED:
        apt_ = apt.Apt(ctx.runner, ctx.yes, cfg["settings"]["conffile_policy"])
        if ctx.dry_run:
            ctx.out.info("would run: " + " ".join(apt_.install_argv(app["packages"])))
            return "planned", "dry run"
        res = apt_.install(app["packages"])
        return ("ok", "installed via APT") if res.ok else ("failed", f"apt-get exit {res.returncode}")
    if st.manager == "direct" and st.state == NOT_INSTALLED:
        return direct_install(ctx, cfg, app, st)
    hint = None
    entry = catalog.CATALOG.get(app["id"], {})
    if entry.get("vendor_repository"):
        hint = (f"Configure the vendor's APT repository yourself (see {entry['source'].get('homepage')}); "
                "wardctl does not create or modify repositories.")
    raise WardctlError(f"cannot install {app['display_name']}: {st.detail}", hint=hint)
