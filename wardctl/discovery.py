"""First-run and repeat discovery. Strictly read-only toward the system.

What can be known:
  * which packages are installed and at which version (dpkg database);
  * whether an enabled APT repository currently offers each package, and
    the repository's origin (apt-cache policy + Release metadata).
What cannot be known:
  * whether a package was originally installed from a downloaded .deb, or
    from which URL. dpkg does not record that, so wardctl reports the
    provenance as unknown rather than inventing it. A Homepage field is
    shown as a hint only; it is never used as a download source.
"""

from dataclasses import dataclass, field

from wardctl import apt, catalog, debpkg, flatpak

DEBIAN_ORIGINS = {"Debian", "Debian Backports"}


@dataclass
class Inventory:
    installed: dict
    policies: dict
    origins: dict
    held: set
    desktop_owners: set
    flatpaks: dict
    comparer: object
    package_count: int = 0

    def origin_of(self, pkg):
        """Set of repository origins offering any version of pkg."""
        pol = self.policies.get(pkg)
        if not pol:
            return set()
        return {self.origins.get(s.description, "?") or "?" for s in pol.repository_sources()}


@dataclass
class DiscoveryResult:
    new_apps: list = field(default_factory=list)       # app ids added to config
    tracked: list = field(default_factory=list)        # app ids already tracked
    candidates: list = field(default_factory=list)     # dicts describing unknown third-party apps
    catalog_missing: list = field(default_factory=list)


def take_inventory(runner, identity, comparer):
    installed = debpkg.query_installed(runner)
    policies = apt.query_policies(runner, installed.keys()) if installed else {}
    origins = apt.query_origins(runner)
    held = {name for name, p in installed.items() if p.held} | apt.held_packages(runner)
    return Inventory(installed=installed, policies=policies, origins=origins, held=held,
                     desktop_owners=debpkg.desktop_file_owners(runner),
                     flatpaks=flatpak.list_installed(runner, identity),
                     comparer=comparer, package_count=len(installed))


def _is_debian_maintained(pkg):
    m = pkg.maintainer.lower()
    return "@debian.org" in m or "lists.debian.org" in m or "alioth" in m or "+deb" in pkg.version


def _candidate(inv, name, pkg):
    origins = inv.origin_of(name) - {"?"}
    if origins and origins <= DEBIAN_ORIGINS:
        return None
    if not origins and _is_debian_maintained(pkg):
        return None  # obsolete Debian package left from an older release
    if name not in inv.desktop_owners:
        return None  # libraries, keyrings, helpers: not interactive applications
    if pkg.section.startswith(("lib", "oldlibs")):
        return None
    status, _ = apt.classify(pkg.version, inv.policies.get(name), inv.comparer)
    return {
        "package": name, "version": pkg.version, "arch": pkg.arch,
        "apt": status, "origins": sorted(origins),
        "homepage_hint": pkg.homepage or None,
        "provenance": "unknown (dpkg does not record where a package came from)",
    }


def deb_record_for(app_id, inv):
    """Catalog record for an installed app, choosing the installed form."""
    entry = catalog.get(app_id)
    alt = (entry.get("alternatives") or {}).get("deb")
    if alt and any(p in inv.installed for p in alt["packages"]):
        entry.update(kind="deb", packages=alt["packages"], source=alt["source"])
        entry.pop("flatpak", None)
    return entry


def is_installed(entry, inv):
    if entry["kind"] == "deb":
        return entry["packages"][0] in inv.installed
    if entry["kind"] == "flatpak":
        fp = entry["flatpak"]
        return (fp["app_id"], fp["installation"]) in inv.flatpaks
    return catalog.probe_exists((entry.get("standalone") or {}).get("probe_paths", []))


def discover(cfg, inv, today):
    """Update cfg in place with newly found catalog apps. Existing records
    (including any user changes) are never overwritten."""
    result = DiscoveryResult()
    apps = cfg["apps"]
    for app_id in catalog.CATALOG:
        entry = deb_record_for(app_id, inv)
        if entry["kind"] == "flatpak":
            fp = entry["flatpak"]
            for inst in ("user", "system"):
                if (fp["app_id"], inst) in inv.flatpaks:
                    fp["installation"] = inst
                    break
        if not is_installed(entry, inv):
            if app_id not in apps:
                result.catalog_missing.append(app_id)
            continue
        if app_id in apps:
            result.tracked.append(app_id)
            continue
        rec = catalog.to_record(entry, registered_by="catalog", today=today)
        rec["provenance"]["inferred"] = ["installed (dpkg database)" if entry["kind"] == "deb"
                                         else "installed (detected on disk)"]
        main = (rec.get("packages") or [None])[0]
        if main and inv.installed.get(main) and inv.installed[main].homepage:
            rec["provenance"]["homepage_hint"] = inv.installed[main].homepage
        apps[app_id] = rec
        result.new_apps.append(app_id)

    covered = {p for a in apps.values() for p in a.get("packages", [])}
    for name, pkg in sorted(inv.installed.items()):
        if name in covered or catalog.for_package(name):
            continue
        cand = _candidate(inv, name, pkg)
        if cand:
            result.candidates.append(cand)
    return result
