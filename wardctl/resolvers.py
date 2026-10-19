"""Official-source release resolvers.

A resolver turns an app's configured source into a Release: the artifact
URL, the version when the vendor publishes reliable metadata, and any
published checksums or signatures. When no reliable version metadata exists
(`version is None`) the caller inspects the package's Debian control data
instead. No resolver guesses a version from URL numbers.
"""

import re
import urllib.parse
from dataclasses import dataclass, field
from html.parser import HTMLParser

from wardctl.errors import ResolveError
from wardctl.netfetch import host_of, redact

PEEK_BYTES = 4 * 1024 * 1024


@dataclass
class Release:
    url: str
    version: str = None          # Debian version from vendor metadata, if published
    label: str = ""              # human release name (tag, upstream version)
    asset_name: str = ""
    checksums: dict = field(default_factory=dict)   # {"sha256"|"sha512": hex}
    checksum_source: str = ""
    signature_url: str = None
    keyring: str = None
    pinned: bool = False
    notes: list = field(default_factory=list)

    def to_dict(self):
        return dict(self.__dict__)

    @classmethod
    def from_dict(cls, d):
        return cls(**d)


@dataclass
class ResolveContext:
    http: object
    arch: str
    debian_major: str
    comparer: object
    min_rollout: float = 1.0


def expand(template, ctx):
    return template.replace("{arch}", ctx.arch).replace("{debian_major}", ctx.debian_major)


class Resolver:
    kind = ""

    def resolve(self, source, ctx):
        raise NotImplementedError


class DirectDebResolver(Resolver):
    """A stable official endpoint that serves a .deb (redirects allowed, each
    hop host-checked). Version comes from the package's control data."""
    kind = "direct-deb"

    def resolve(self, source, ctx):
        url = expand(source["url"], ctx)
        rel = Release(url=url, pinned=bool(source.get("pinned")), label="(from package metadata)")
        if rel.pinned:
            rel.notes.append("pinned URL: always serves the same release; newer releases are not discovered")
        return rel


class GitHubReleaseResolver(Resolver):
    """Stable (non-draft, non-prerelease) releases of an explicitly
    configured official repository, with exactly one matching asset."""
    kind = "github-release"
    API = "https://api.github.com/repos/{repo}/releases?per_page=20"

    def resolve(self, source, ctx):
        repo = source["repo"]
        pattern = re.compile(expand(source["asset_pattern"], ctx))
        tag_re = re.compile(source["tag_pattern"]) if source.get("tag_pattern") else None
        releases = ctx.http.get_json(self.API.format(repo=repo), source["approved_hosts"],
                                     headers={"Accept": "application/vnd.github+json",
                                              "X-GitHub-Api-Version": "2022-11-28"})
        if not isinstance(releases, list):
            raise ResolveError(f"unexpected GitHub API response for {repo}")
        skipped = []
        for rel in releases:
            if not isinstance(rel, dict) or rel.get("draft") or rel.get("prerelease"):
                continue
            tag = str(rel.get("tag_name", ""))
            if tag_re and not tag_re.fullmatch(tag):
                continue
            assets = [a for a in rel.get("assets", []) if isinstance(a, dict)]
            matches = [a for a in assets if pattern.fullmatch(str(a.get("name", "")))]
            if len(matches) > 1:
                raise ResolveError(f"{repo} release {tag} has {len(matches)} assets matching "
                                   f"{pattern.pattern!r}; refusing to choose",
                                   hint="Tighten asset_pattern in the app's source configuration.")
            if not matches:
                skipped.append(tag)
                continue
            asset = matches[0]
            url = str(asset.get("browser_download_url", ""))
            if host_of(url) != "github.com" or f"/{repo}/releases/download/".lower() not in url.lower():
                raise ResolveError(f"asset URL {redact(url)} is not a {repo} release download")
            out = Release(url=url, label=tag, asset_name=asset["name"])
            digest = str(asset.get("digest") or "")
            if digest.startswith("sha256:") and re.fullmatch(r"[0-9a-f]{64}", digest[7:]):
                out.checksums["sha256"] = digest[7:]
                out.checksum_source = "GitHub API asset digest (transfer integrity, not a publisher signature)"
            sig = source.get("signature")
            if sig:
                sig_name = asset["name"] + sig["suffix"]
                sig_asset = next((a for a in assets if a.get("name") == sig_name), None)
                if not sig_asset:
                    raise ResolveError(f"{repo} {tag}: expected signature {sig_name} is missing")
                out.signature_url = str(sig_asset.get("browser_download_url"))
                out.keyring = sig["keyring"]
            if skipped:
                out.notes.append(f"newer release(s) {', '.join(skipped)} have no matching asset")
            return out
        raise ResolveError(f"no stable release of {repo} has an asset matching {pattern.pattern!r}",
                           hint="The project may not publish a build for this distribution/architecture.")


class ProtonVersionJsonResolver(Resolver):
    """Proton's version.json manifest (the same one Proton's desktop apps
    use). Picks the highest version in the configured channel that is fully
    rolled out, and uses the published SHA-512."""
    kind = "vendor-json"

    def resolve(self, source, ctx):
        url = expand(source["url"], ctx)
        data = ctx.http.get_json(url, source["approved_hosts"])
        releases = data.get("Releases") if isinstance(data, dict) else None
        if not isinstance(releases, list):
            raise ResolveError(f"{redact(url)} is not a Proton version manifest")
        channel = source.get("channel", "Stable")
        eligible = []
        for rel in releases:
            if not isinstance(rel, dict) or rel.get("CategoryName") != channel:
                continue
            rollout = rel.get("RolloutPercentage", rel.get("RolloutProportion", 1))
            if not isinstance(rollout, (int, float)) or rollout < ctx.min_rollout:
                continue
            files = [f for f in rel.get("File", []) if isinstance(f, dict)
                     and str(f.get("Url", "")).endswith(".deb")]
            version = str(rel.get("Version", ""))
            if len(files) == 1 and re.fullmatch(r"[0-9][A-Za-z0-9.+~-]*", version):
                eligible.append((version, files[0]))
        if not eligible:
            raise ResolveError(f"no fully rolled-out {channel} .deb release in {redact(url)}")
        best = ctx.comparer.newest([v for v, _ in eligible])
        version, f = next(item for item in eligible if item[0] == best)
        rel = Release(url=str(f["Url"]), version=version, label=f"{channel} {version}",
                      asset_name=str(f["Url"]).rsplit("/", 1)[-1])
        checksum = str(f.get("Sha512CheckSum", "")).lower()
        if re.fullmatch(r"[0-9a-f]{128}", checksum):
            rel.checksums["sha512"] = checksum
            rel.checksum_source = "SHA-512 from vendor manifest"
        return rel


class _Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        for name, value in attrs:
            if name in ("href", "src") and value:
                self.links.append(value)


class HtmlLinkResolver(Resolver):
    """Vendor-specific HTML download page adapter. The configured pattern
    must identify exactly one download link on the page; when several match
    the resolver fails instead of choosing the numerically largest URL."""
    kind = "html-link"

    def resolve(self, source, ctx):
        page = source["page_url"]
        _, raw = ctx.http.get_bytes(page, source["approved_hosts"], max_bytes=5 * 1024 * 1024)
        parser = _Links()
        parser.feed(raw.decode("utf-8", "replace"))
        pattern = re.compile(expand(source["link_pattern"], ctx))
        found = sorted({urllib.parse.urljoin(page, link) for link in parser.links
                        if pattern.fullmatch(urllib.parse.urljoin(page, link))})
        if not found:
            raise ResolveError(f"no download link matching the adapter pattern on {redact(page)}",
                               hint="The page layout may have changed; the adapter needs maintenance.")
        if len(found) > 1:
            raise ResolveError(f"{len(found)} links on {redact(page)} match the adapter pattern; "
                               "refusing to guess which is newest",
                               hint="Use a vendor 'latest' endpoint or manifest instead.")
        return Release(url=found[0], label="(from package metadata)")


RESOLVERS = {r.kind: r for r in (DirectDebResolver(), GitHubReleaseResolver(),
                                 ProtonVersionJsonResolver(), HtmlLinkResolver())}


def resolve(source, ctx):
    resolver = RESOLVERS.get(source.get("resolver"))
    if resolver is None:
        raise ResolveError(f"no resolver for source type {source.get('resolver')!r}")
    return resolver.resolve(source, ctx)
