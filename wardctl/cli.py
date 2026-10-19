"""Command-line interface for wardctl."""

import argparse
import json
import os
import sys

from wardctl import (__version__, apt, catalog, config, debpkg, discovery, engine, identity, locks,
                       platforminfo, privilege)
from wardctl import runner as R
from wardctl.errors import (EXIT_FATAL, EXIT_OK, EXIT_PARTIAL, EXIT_UPDATES, EXIT_USAGE, ConfigError,
                              WardctlError)
from wardctl.netfetch import HttpClient

EPILOG = """\
Updating:
  sudo wardctl update            refresh APT metadata, run apt-get upgrade, then update
                                   tracked apps that have no APT source
  wardctl update                 same; asks for sudo itself when installed system-wide
  wardctl update --dry-run       show the plan without changing anything

Exit codes:
  0  success / nothing pending       10  updates available (check)
  1  fatal failure                   20  partial failure (some steps failed)
  2  usage error                     75  another wardctl run or APT/dpkg holds a lock
  78 configuration malformed or unsafe (file left untouched; repair it)
"""


class Output:
    def __init__(self, stdout=None, stderr=None):
        self.stdout = stdout or sys.stdout
        self.stderr = stderr or sys.stderr

    def info(self, msg=""):
        print(msg, file=self.stdout, flush=True)

    def warn(self, msg):
        print(f"warning: {msg}", file=self.stderr, flush=True)

    def error(self, msg):
        print(f"error: {msg}", file=self.stderr, flush=True)

    def section(self, title):
        self.info(f"\n== {title} ==")

    def table(self, headers, rows):
        rows = [tuple(str(c) for c in r) for r in rows]
        widths = [max([len(h)] + [len(r[i]) for r in rows]) for i, h in enumerate(headers)]
        fmt = "  ".join(f"{{:<{w}}}" for w in widths[:-1]) + "  {}"
        self.info(fmt.format(*headers))
        for r in rows:
            self.info(fmt.format(*r))


# ------------------------------------------------------------------ parser

def build_parser():
    p = argparse.ArgumentParser(
        prog="wardctl", formatter_class=argparse.RawDescriptionHelpFormatter, epilog=EPILOG,
        description="wardctl: APT-first installation and updates for Debian, with verified official "
                    "sources for applications APT cannot update.")
    p.add_argument("--version", action="version", version=f"wardctl {__version__}")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-y", "--yes", action="store_true",
                        help="answer yes; run APT noninteractively (keeps existing conffiles by default)")
    sub = p.add_subparsers(dest="command", metavar="COMMAND")

    sub.add_parser("init", parents=[common], help="create ~/.wardctl and run first discovery (read-only)")
    d = sub.add_parser("discover", parents=[common], help="re-scan installed software (read-only toward the system)")
    d.add_argument("--json", action="store_true")
    ls = sub.add_parser("list", parents=[common], help="list tracked applications")
    ls.add_argument("--all", action="store_true", help="also list catalog apps that are not tracked")
    ls.add_argument("--json", action="store_true")
    s = sub.add_parser("status", parents=[common], help="installed versions and how each app is managed (offline)")
    s.add_argument("app", nargs="?")
    s.add_argument("--json", action="store_true")
    c = sub.add_parser("check", parents=[common], help="check for updates without installing (exit 10 if any)")
    c.add_argument("app", nargs="?")
    c.add_argument("--refresh", action="store_true", help="run apt-get update first (needs root)")
    c.add_argument("--json", action="store_true")

    a = sub.add_parser("add", parents=[common], help="register an app and its update source (does not install)")
    a.add_argument("app", nargs="?", help="catalog app id, or id for --package/--url")
    a.add_argument("--url", help="official .deb URL, 'latest' endpoint, GitHub repository, or download page")
    a.add_argument("--package", help="register an installed Debian package")
    a.add_argument("--name", help="display name")
    a.add_argument("--asset-pattern", help="GitHub asset regex (use {arch})")
    a.add_argument("--allow-host", action="append", default=[], help="extra approved download host (repeatable)")
    pin = a.add_mutually_exclusive_group()
    pin.add_argument("--pinned", dest="pinned", action="store_const", const=True,
                     help="URL serves one fixed release")
    pin.add_argument("--endpoint", dest="pinned", action="store_const", const=False,
                     help="URL always serves the latest release")

    i = sub.add_parser("install", parents=[common], help="install an app on explicit request and track it")
    i.add_argument("app", nargs="?")
    i.add_argument("--url", help="install from an official URL (registered first)")
    i.add_argument("--deb", action="store_true", help="use the app's official .deb instead of its Flatpak")
    i.add_argument("--name")
    i.add_argument("--asset-pattern")
    i.add_argument("--allow-host", action="append", default=[])
    i.add_argument("--dry-run", action="store_true")

    u = sub.add_parser("update", parents=[common], help="refresh APT, upgrade, then update tracked apps")
    u.add_argument("app", nargs="?", help="update only this app (and its required dependencies)")
    g = u.add_mutually_exclusive_group()
    g.add_argument("--apt-only", action="store_true", help="only apt-get update + apt-get upgrade")
    g.add_argument("--apps-only", action="store_true", help="only tracked apps; no system-wide upgrade")
    u.add_argument("--full-upgrade", action="store_true",
                   help="use apt-get full-upgrade (may remove packages); never the default")
    u.add_argument("--dry-run", action="store_true", help="show the plan; change nothing")

    r = sub.add_parser("remove", parents=[common], help="stop tracking an app (does not uninstall it)")
    r.add_argument("app")

    st = sub.add_parser("set", parents=[common], help="change an app's registration explicitly")
    st.add_argument("app")
    st.add_argument("--policy", choices=config.POLICIES,
                    help="prefer-apt (default) | apt-only | direct-only (override APT) | check-only")
    st.add_argument("--allow-held-update", choices=("yes", "no"),
                    help="let direct-source updates change a held package")
    st.add_argument("--package", help="accept a legitimate package rename")

    sub.add_parser("doctor", parents=[common], help="diagnose configuration, permissions and system state")
    return p


# --------------------------------------------------------------- context

NEEDS_ROOT = {"update", "install"}


def needs_root(args):
    if args.command in NEEDS_ROOT:
        return not getattr(args, "dry_run", False)
    return args.command == "check" and args.refresh


class Deps:
    """Injectable dependencies (tests replace these)."""
    def __init__(self):
        self.runner = R.Runner()
        self.http = None
        self.env = os.environ
        self.euid = os.geteuid()
        self.getpwuid = None
        self.stdout = None
        self.stderr = None
        self.interactive = sys.stdin.isatty()
        self.platform = None
        self.system_cache = engine.SYSTEM_CACHE
        self.system_lock = locks.SYSTEM_LOCK
        self.apt_lock_probe = locks.apt_lock_holder
        self.execv = os.execv
        self.confirm_fn = None


def build_context(args, deps, out):
    kw = {"getpwuid": deps.getpwuid} if deps.getpwuid else {}
    ident = identity.resolve(env=deps.env, euid=deps.euid, **kw)
    plat = deps.platform or platforminfo.detect(deps.runner)
    dry = bool(getattr(args, "dry_run", False))
    store = config.Store(ident, read_only=dry)
    return engine.Context(runner=deps.runner, identity=ident, platform=plat, store=store,
                          http=deps.http or HttpClient(), out=out, yes=args.yes if hasattr(args, "yes") else False,
                          dry_run=dry, interactive=deps.interactive, system_cache=deps.system_cache,
                          system_lock_path=deps.system_lock, apt_lock_probe=deps.apt_lock_probe,
                          confirm_fn=deps.confirm_fn)


def load_cfg(ctx, required=True):
    cfg, migrated = ctx.store.load_config(allow_missing=True)
    if not ctx.store.exists() and required:
        raise ConfigError("wardctl has not been initialised for this user", hint="Run `wardctl init`.")
    if migrated and not ctx.store.read_only:
        ctx.store.backup_config(f".bak-schema-{cfg['schema_version'] - 1}")
        ctx.store.save_config(cfg)
        ctx.out.info(f"Migrated {ctx.store.paths.config} to schema {cfg['schema_version']} (backup kept).")
    return cfg


# ---------------------------------------------------------------- commands

def cmd_none(ctx, args):
    out = ctx.out
    out.info(f"wardctl {__version__} — {ctx.platform.describe()}, user {ctx.identity.describe()}")
    if not ctx.store.exists():
        out.info("\nNot initialised yet. Start with:\n  wardctl init        (read-only discovery)")
    else:
        cfg = load_cfg(ctx)
        out.info(f"\n{len(cfg['apps'])} tracked application(s). `wardctl status` shows details, "
                 "`wardctl check` looks for updates.")
    out.info("\nTo update the system and tracked apps:\n  sudo wardctl update    (or `wardctl update --dry-run` "
             "to preview)\n\nRun `wardctl --help` for all commands.")
    return EXIT_OK


def _discover_and_save(ctx, cfg, as_json=False):
    inv = discovery.take_inventory(ctx.runner, ctx.identity, debpkg.VersionComparer(ctx.runner))
    res = discovery.discover(cfg, inv, config.today())
    state = ctx.store.load_state()
    state["discovery"] = {
        "at": config.now(), "platform": ctx.platform.describe(), "installed_packages": inv.package_count,
        "candidates": res.candidates, "tracked_added": res.new_apps,
    }
    ctx.store.save_config(cfg)
    ctx.store.save_state(state)
    out = ctx.out
    if as_json:
        out.info(json.dumps({"new": res.new_apps, "tracked": res.tracked, "candidates": res.candidates,
                             "catalog_not_installed": res.catalog_missing}, indent=2))
        return EXIT_OK
    out.info(f"Scanned {inv.package_count} installed packages (dpkg database) and "
             f"{len(inv.flatpaks)} Flatpak apps. Nothing was installed or changed on the system.")
    snap = engine.Snapshot(inv.installed, inv.policies, inv.held, inv.comparer, inv.flatpaks)
    if res.new_apps:
        out.section("Newly tracked (known applications found installed)")
        engine.print_statuses(out, [engine.evaluate(ctx, cfg, cfg["apps"][a], snap) for a in res.new_apps])
    if res.tracked:
        out.info(f"\nAlready tracked: {', '.join(res.tracked)}")
    if res.candidates:
        out.section("Other third-party applications (not tracked)")
        out.table(("PACKAGE", "VERSION", "APT", "ORIGIN", "HOMEPAGE (hint only)"),
                  [(c["package"], c["version"], c["apt"], ",".join(c["origins"]) or "none",
                    c["homepage_hint"] or "-") for c in res.candidates])
        out.info("Provenance of these packages is unknown: dpkg does not record whether a package came from "
                 "a downloaded .deb or where from.\nTrack one with:  wardctl add --package NAME "
                 "[--url OFFICIAL_SOURCE]")
    if res.catalog_missing:
        out.info(f"\nKnown but not installed (install explicitly with `wardctl install APP`): "
                 f"{', '.join(res.catalog_missing)}")
    return EXIT_OK


def cmd_init(ctx, args):
    if ctx.store.exists():
        cfg = load_cfg(ctx)
        ctx.out.info(f"{ctx.store.paths.config} already exists; re-running discovery.")
    else:
        cfg = config.new_config()
        ctx.out.info(f"Creating {ctx.store.paths.root} for {ctx.identity.describe()}.")
    with ctx.store.user_lock() as _:
        return _discover_and_save(ctx, cfg)


def cmd_discover(ctx, args):
    cfg = load_cfg(ctx)
    with ctx.store.user_lock():
        return _discover_and_save(ctx, cfg, args.json)


def cmd_list(ctx, args):
    cfg = load_cfg(ctx)
    rows = []
    for a in cfg["apps"].values():
        src = a.get("source", {})
        rows.append({"id": a["id"], "name": a["display_name"], "kind": a["kind"],
                     "packages": a.get("packages", []), "source": src.get("resolver"),
                     "policy": a.get("update_policy", "prefer-apt"),
                     "verification": a.get("verification", {}).get("status"),
                     "registered_by": a.get("provenance", {}).get("registered_by"), "tracked": True})
    if args.all:
        for app_id, e in catalog.CATALOG.items():
            if app_id not in cfg["apps"]:
                rows.append({"id": app_id, "name": e["display_name"], "kind": e["kind"],
                             "packages": e.get("packages", []), "source": e["source"]["resolver"],
                             "policy": e.get("update_policy"), "verification": e["verification"]["status"],
                             "registered_by": "catalog", "tracked": False})
    if args.json:
        ctx.out.info(json.dumps(rows, indent=2))
        return EXIT_OK
    ctx.out.table(("APP", "KIND", "SOURCE", "POLICY", "VERIFIED", "TRACKED", "NAME"),
                  [(r["id"], r["kind"], r["source"], r["policy"], r["verification"],
                    "yes" if r["tracked"] else "no", r["name"]) for r in rows])
    return EXIT_OK


def cmd_status(ctx, args):
    cfg = load_cfg(ctx)
    apps = engine.tracked_apps(cfg, args.app)
    snap = engine.load_snapshot(ctx, apps)
    statuses = [engine.evaluate(ctx, cfg, a, snap, resolve=False) for a in apps]
    if args.json:
        ctx.out.info(json.dumps([s.to_dict() for s in statuses], indent=2))
        return EXIT_OK
    ctx.out.info("Installed versions come from the dpkg database; repository state from APT's current "
                 "metadata. No network access.")
    engine.print_statuses(ctx.out, statuses)
    state = ctx.store.load_state()
    if state.get("last_check"):
        ctx.out.info(f"\nLast check: {state['last_check']['at']} (`wardctl check` to refresh)")
    return EXIT_OK


def cmd_check(ctx, args):
    cfg = load_cfg(ctx)
    if args.refresh:
        ctx.platform.require_supported("Refreshing APT metadata")
        res = apt.Apt(ctx.runner).refresh()
        if not res.ok:
            ctx.out.error("apt-get update failed; results below use the previous metadata.")
    statuses, system = engine.check(ctx, cfg, args.app)
    code = engine.check_exit(statuses, system)
    if not ctx.store.read_only:
        state = ctx.store.load_state()
        state["last_check"] = {"at": config.now(), "results": {s.app_id: s.to_dict() for s in statuses},
                               "system_upgrades": len(system.upgrades) if system else None}
        ctx.store.save_state(state)
    if args.json:
        ctx.out.info(json.dumps({"apps": [s.to_dict() for s in statuses],
                                 "system": None if system is None else {
                                     "upgrades": [list(u) for u in system.upgrades],
                                     "kept_back": system.kept_back}, "exit_code": code}, indent=2))
        return code
    if not args.refresh:
        ctx.out.info("APT data is from the last `apt-get update` (use --refresh, as root, to refresh first).")
    engine.print_statuses(ctx.out, statuses)
    if system is not None:
        ctx.out.info(f"\nSystem: {len(system.upgrades)} package(s) upgradable with apt-get upgrade"
                     + (f", kept back: {' '.join(system.kept_back)}" if system.kept_back else ""))
    n = sum(s.state == engine.UPDATE_AVAILABLE for s in statuses)
    ctx.out.info(f"\n{n} application update(s) available." + (" Run: sudo wardctl update" if code == EXIT_UPDATES else ""))
    return code


def _with_mutation_locks(ctx, fn):
    if ctx.dry_run:
        return fn()
    with ctx.store.user_lock():
        # Root-owned in production (the process is root when it gets here).
        lock = locks.FileLock(ctx.system_lock_path, os.geteuid(), "Another wardctl system operation")
        with lock:
            return fn()


def cmd_update(ctx, args):
    cfg = load_cfg(ctx)
    if args.full_upgrade and (args.apps_only or args.app):
        raise WardctlError("--full-upgrade only applies to the system-wide upgrade")
    if args.app:
        engine.tracked_apps(cfg, args.app)
    if ctx.dry_run:
        ctx.platform.require_supported("Planning updates")
        ctx.out.info("DRY RUN: nothing will be installed, APT metadata and repositories are not modified, "
                     "and no wardctl state is written. Release metadata may be fetched over the network, and "
                     "for sources without version metadata the first few MB of the package are downloaded to a "
                     "temporary directory to read its control data.")
    else:
        engine.preflight(ctx)

    def work():
        summary, _ = engine.run_update(ctx, cfg, args.app, args.apt_only, args.apps_only, args.full_upgrade)
        if not ctx.dry_run:
            state = ctx.store.load_state()
            state["last_update"] = {"at": config.now(), "steps": summary.steps, "exit": summary.exit_code()}
            ctx.store.save_state(state)
            ctx.store.save_config(cfg)
            ctx.store.log(f"update exit={summary.exit_code()} steps={summary.steps}")
        engine.print_summary(ctx.out, summary)
        return summary.exit_code()
    return _with_mutation_locks(ctx, work)


def _registration(ctx, cfg, args):
    if args.url:
        rec, control = engine.register_from_url(
            ctx, cfg, args.url, app_id=args.app, name=args.name, package=getattr(args, "package", None),
            asset_pattern=args.asset_pattern, allow_hosts=args.allow_host,
            pinned=getattr(args, "pinned", None))
        if control:
            ctx.out.info(f"Verified package identity: {control['package']} {control['version']} ({control['arch']})")
        return rec
    if not args.app:
        raise WardctlError("name an application or give --url")
    entry = catalog.get(args.app)
    if entry is None:
        raise WardctlError(f"{args.app!r} is not in the built-in catalog",
                            hint="Use --url with an official source, or `wardctl add --package NAME`.")
    if getattr(args, "deb", False):
        alt = (entry.get("alternatives") or {}).get("deb")
        if not alt:
            raise WardctlError(f"{args.app} has no alternative .deb source")
        entry.update(kind="deb", packages=alt["packages"], source=alt["source"])
        entry.pop("flatpak", None)
    return catalog.to_record(entry, registered_by="user", today=config.today())


def cmd_add(ctx, args):
    cfg = load_cfg(ctx)
    if args.package and not args.url:
        if not config.PKG_RE.match(args.package):
            raise WardctlError(f"invalid package name {args.package!r}")
        known = catalog.for_package(args.package)
        installed = debpkg.query_installed(ctx.runner, [args.package]).get(args.package)
        if known and not args.app:
            args.app = known
            rec = _registration(ctx, cfg, args)
        else:
            app_id = args.app or args.package
            if not config.ID_RE.match(app_id):
                raise WardctlError(f"invalid application id {app_id!r}")
            rec = {"id": app_id, "display_name": args.name or args.package, "kind": "deb",
                   "packages": [args.package], "source": {"resolver": "apt", "approved_hosts": []},
                   "architectures": [], "update_policy": "prefer-apt", "allow_held_update": False,
                   "verification": {"status": "unverified", "checked_on": config.today(),
                                    "method": "registered by the user; APT only until a source is added"},
                   "provenance": {"registered_by": "user", "user_supplied": ["packages"],
                                  "inferred": [], "install_origin": "unknown"},
                   "added_at": config.today()}
            if installed:
                rec["identity"] = {"package": args.package, "architecture": installed.arch,
                                   "verified_on": config.today()}
                if installed.homepage:
                    rec["provenance"]["homepage_hint"] = installed.homepage
            else:
                ctx.out.warn(f"{args.package} is not installed; registered for future installation via APT.")
    else:
        rec = _registration(ctx, cfg, args)
    if rec["id"] in cfg["apps"]:
        old = cfg["apps"][rec["id"]]
        if args.url:
            # Replacing the source of an existing registration keeps its identity lock.
            old_pkg = (old.get("identity") or {}).get("package") or old["packages"][0]
            if old_pkg != rec["packages"][0]:
                raise WardctlError(
                    f"{rec['id']} is registered as package {old_pkg!r} but the URL serves {rec['packages'][0]!r}",
                    hint=f"If this is a legitimate rename, run `wardctl set {rec['id']} --package "
                         f"{rec['packages'][0]}` first.")
            old["source"] = rec["source"]
            old["verification"] = rec["verification"]
            old.setdefault("provenance", {}).setdefault("user_supplied", []).append("source")
            old["updated_at"] = config.today()
            rec = old
        else:
            ctx.out.info(f"{rec['id']} is already tracked.")
            return EXIT_OK
    with ctx.store.user_lock():
        cfg["apps"][rec["id"]] = rec
        ctx.store.save_config(cfg)
    ctx.out.info(f"Registered {rec['id']} ({rec['display_name']}), source: {rec['source']['resolver']}. "
                 "Nothing was installed.")
    if rec["verification"].get("status") in ("pending", "unsupported"):
        ctx.out.info(f"Note: {rec['verification'].get('method')}")
    return EXIT_OK


def cmd_install(ctx, args):
    cfg = load_cfg(ctx, required=False)
    if not args.app and not args.url:
        raise WardctlError("name an application or give --url")
    if args.dry_run:
        ctx.platform.require_supported("Planning an install")
    else:
        engine.preflight(ctx)
    if args.app in cfg["apps"] and not args.url:
        rec = cfg["apps"][args.app]
    else:
        rec = _registration(ctx, cfg, args)
    snap = engine.load_snapshot(ctx, [rec])

    def work():
        status, detail = engine.run_install(ctx, cfg, rec, snap)
        if status in ("ok", "nothing") and not ctx.dry_run:
            if status == "ok":
                rec.setdefault("provenance", {})["install_origin"] = "wardctl"
            cfg["apps"][rec["id"]] = rec
            ctx.store.save_config(cfg)
        ctx.out.info(f"{rec['id']}: {status} ({detail})")
        return EXIT_OK if status in ("ok", "nothing", "planned") else EXIT_PARTIAL
    return _with_mutation_locks(ctx, work)


def cmd_remove(ctx, args):
    cfg = load_cfg(ctx)
    if args.app not in cfg["apps"]:
        raise WardctlError(f"{args.app!r} is not tracked")
    with ctx.store.user_lock():
        del cfg["apps"][args.app]
        ctx.store.save_config(cfg)
    ctx.out.info(f"Stopped tracking {args.app}. The software itself was NOT uninstalled "
                 "(use apt-get remove if you want that).")
    return EXIT_OK


def cmd_set(ctx, args):
    cfg = load_cfg(ctx)
    app = engine.tracked_apps(cfg, args.app)[0]
    changed = []
    if args.policy:
        app["update_policy"] = args.policy
        changed.append(f"update_policy={args.policy}")
        if args.policy == "direct-only":
            ctx.out.warn("direct-only overrides APT: updates come from the direct source even when an APT "
                         "repository offers the package. apt-get upgrade may still replace it with a newer "
                         "repository version, and you lose APT's signed-repository verification for it.")
    if args.allow_held_update:
        app["allow_held_update"] = args.allow_held_update == "yes"
        changed.append(f"allow_held_update={app['allow_held_update']}")
    if args.package:
        if not config.PKG_RE.match(args.package):
            raise WardctlError(f"invalid package name {args.package!r}")
        old = (app.get("identity") or {}).get("package") or app["packages"][0]
        app["packages"][0] = args.package
        if app.get("identity"):
            app["identity"]["package"] = args.package
            app["identity"]["verified_on"] = config.today()
        app.setdefault("provenance", {}).setdefault("user_supplied", []).append("packages")
        changed.append(f"package {old} -> {args.package}")
    if not changed:
        raise WardctlError("nothing to change; see `wardctl set --help`")
    app["updated_at"] = config.today()
    with ctx.store.user_lock():
        ctx.store.save_config(cfg)
    ctx.out.info(f"{args.app}: " + ", ".join(changed))
    return EXIT_OK


def cmd_doctor(ctx, args):
    out = ctx.out
    problems = 0

    def report(ok, msg, hint=None):
        nonlocal problems
        out.info(f"[{'ok' if ok else '!!'}] {msg}")
        if not ok:
            problems += 1
            if hint:
                out.info(f"     {hint}")

    report(ctx.platform.supported, f"platform: {ctx.platform.describe()}",
           "Only Debian 13 amd64 is tested; mutating commands are refused elsewhere.")
    out.info(f"[..] user: {ctx.identity.describe()}, state in {ctx.store.paths.root}")
    for tool in (R.APT_GET, R.APT_CACHE, R.APT_MARK, R.DPKG, R.DPKG_QUERY, R.DPKG_DEB, R.GPGV, R.SUDO):
        report(ctx.runner.exists(tool), f"tool {tool}")
    out.info(f"[..] optional: flatpak {'present' if ctx.runner.exists(R.FLATPAK) else 'not installed'}")
    try:
        ctx.store.validate_dirs()
        if ctx.store.exists():
            cfg, migrated = ctx.store.load_config()
            report(True, f"config valid ({len(cfg['apps'])} apps, schema {cfg['schema_version']}"
                         + (", needs migration" if migrated else "") + ")")
        else:
            report(False, "not initialised", "Run `wardctl init`.")
    except WardctlError as exc:
        report(False, str(exc), exc.hint)
    holder = None
    try:
        holder = ctx.apt_lock_probe()
    except OSError:
        pass
    report(holder is None, "APT/dpkg locks free" if holder is None else
           f"APT/dpkg lock {holder[0]} held by PID {holder[1]} ({locks.process_name(holder[1])})")
    origins = apt.query_origins(ctx.runner)
    seen = {}
    for desc in origins:
        if desc.strip() == apt.STATUS_FILE:
            continue
        seen.setdefault(desc, 0)
        seen[desc] += 1
    report(True, f"{len(seen)} APT package index(es) configured")
    report(not debpkg.reboot_required(), "no reboot pending",
           "/run/reboot-required exists; reboot when convenient (wardctl never reboots).")
    launcher = os.path.realpath(sys.argv[0])
    trusted = privilege.is_trusted_path(launcher) and privilege.is_trusted_path(privilege.package_parent())
    out.info(f"[..] program: {privilege.package_parent()} "
             f"({'root-owned installation; can elevate with sudo' if trusted else 'not a root-owned install; will not self-elevate'})")
    return EXIT_OK if problems == 0 else EXIT_PARTIAL


COMMANDS = {"init": cmd_init, "discover": cmd_discover, "list": cmd_list, "status": cmd_status,
            "check": cmd_check, "add": cmd_add, "install": cmd_install, "update": cmd_update,
            "remove": cmd_remove, "set": cmd_set, "doctor": cmd_doctor}


def main(argv=None, deps=None):
    deps = deps or Deps()
    argv = list(sys.argv[1:] if argv is None else argv)
    out = Output(deps.stdout, deps.stderr)
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return EXIT_OK if exc.code == 0 else EXIT_USAGE
    try:
        if args.command and needs_root(args) and deps.euid != 0:
            elevated = privilege.elevation_argv(argv)
            out.info("Root privileges are needed; re-running with sudo: " + " ".join(elevated[2:]))
            deps.execv(elevated[0], elevated)
            return EXIT_FATAL  # only reached if execv is mocked
        ctx = build_context(args, deps, out)
        if args.command is None:
            return cmd_none(ctx, args)
        return COMMANDS[args.command](ctx, args)
    except WardctlError as exc:
        out.error(str(exc))
        if exc.hint:
            print(f"hint: {exc.hint}", file=out.stderr)
        return exc.exit_code
    except KeyboardInterrupt:
        out.error("interrupted")
        return EXIT_FATAL
