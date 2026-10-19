"""Unprivileged preparation of a direct-source update.

`prepare()` resolves the official release, then either reads only the head of
the package (mode "peek", enough for dpkg-deb to read the control data) or
downloads the full artifact (mode "download"), verifies published checksums
and signatures, and inspects the package identity.

When wardctl runs as root for an invoking user, this runs in a separate
process that has fully dropped to that user (`python3 -I -m
wardctl.worker`, request on stdin, JSON result on stdout), so untrusted
network data is never parsed with root privileges.
"""

import json
import os
import re
import shutil
import sys
import tempfile
import urllib.parse

from wardctl import debpkg, resolvers, verify
from wardctl.catalog import GITHUB_HOSTS
from wardctl.errors import WardctlError, ResolveError, VerificationError
from wardctl.netfetch import HttpClient, redact
from wardctl.runner import Runner


def _safe_name(text):
    return "".join(c if c.isalnum() or c in ".+-_" else "_" for c in text)[:80] or "package"


def prepare(request, runner=None, http=None):
    runner = runner or Runner()
    http = http or HttpClient()
    app = request["app"]
    comparer = debpkg.VersionComparer(runner)
    ctx = resolvers.ResolveContext(http=http, arch=request["arch"], debian_major=request["debian_major"],
                                   comparer=comparer, min_rollout=request.get("min_rollout", 1.0))
    source = app["source"]
    hosts = source["approved_hosts"]
    release = resolvers.resolve(source, ctx)
    result = {"ok": True, "release": release.to_dict(), "control": None, "artifact": None}
    staging = request.get("staging_dir") or tempfile.gettempdir()

    if request["mode"] == "metadata" and release.version:
        result["control"] = None
        result["log"] = http.log
        return result

    workdir = tempfile.mkdtemp(prefix="prep-", dir=staging)
    try:
        if request["mode"] in ("peek", "metadata"):
            _, head = http.peek(release.url, hosts, resolvers.PEEK_BYTES)
            path = os.path.join(workdir, "head.deb")
            with open(path, "wb") as fh:
                fh.write(head)
            info = debpkg.inspect_deb(runner, path)
            shutil.rmtree(workdir, ignore_errors=True)
            workdir = None
        else:
            path = os.path.join(workdir, _safe_name(app["id"]) + ".deb")
            dl = http.download(release.url, hosts, path, request["max_bytes"])
            matched = verify.check_checksums(release.checksums, dl.sha256, dl.sha512)
            sig_path = None
            if release.signature_url:
                sig_path = path + ".sig"
                http.download(release.signature_url, hosts, sig_path, 64 * 1024)
                verify.check_signature(runner, release.keyring, sig_path, path)
            info = debpkg.inspect_deb(runner, path)
            result["artifact"] = {"dir": workdir, "path": path, "sig_path": sig_path, "size": dl.size,
                                  "sha256": dl.sha256, "sha512": dl.sha512, "checksums_matched": matched,
                                  "signature_verified": bool(sig_path), "final_url": redact(dl.final_url)}
        debpkg.check_identity(info, app, request["arch"])
        if release.version and comparer.compare(release.version, info.version) != 0:
            raise VerificationError(
                f"vendor metadata says version {release.version} but the package is {info.version}")
        result["control"] = info.__dict__
        result["log"] = http.log
        return result
    except BaseException:
        if workdir:
            shutil.rmtree(workdir, ignore_errors=True)
        raise


def _github_source(url, request, http, ctx):
    parts = [p for p in urllib.parse.urlsplit(url).path.split("/") if p]
    if len(parts) < 2:
        raise ResolveError("GitHub URL must name a repository: https://github.com/OWNER/REPO")
    repo = f"{parts[0]}/{parts[1]}"
    hosts = sorted(set(request["allowed_hosts"]) | set(GITHUB_HOSTS))
    pattern = request.get("asset_pattern")
    if not pattern:
        releases = http.get_json(resolvers.GitHubReleaseResolver.API.format(repo=repo), hosts)
        stable = [r for r in releases if isinstance(r, dict) and not r.get("draft") and not r.get("prerelease")]
        arch = request["arch"]
        for rel in stable:
            names = [a.get("name", "") for a in rel.get("assets", [])
                     if re.fullmatch(rf".*[_.-]{re.escape(arch)}\.deb", str(a.get("name", "")))]
            if not names:
                continue
            if len(names) > 1:
                raise ResolveError(f"{repo} {rel.get('tag_name')} has several {arch} .deb assets: "
                                   f"{', '.join(names)}", hint="Choose one with --asset-pattern REGEX.")
            name = names[0]
            m = re.search(r"\d+(?:\.\d+)+", str(rel.get("tag_name", "")))
            if not m or m.group(0) not in name:
                raise ResolveError(f"cannot derive a version-independent pattern from {name!r}",
                                   hint="Supply --asset-pattern REGEX (use {arch} for the architecture).")
            pre, _, post = name.partition(m.group(0))
            pattern = (re.escape(pre) + r"[0-9][0-9.]*" + re.escape(post)).replace(re.escape(arch), "{arch}")
            break
        else:
            raise ResolveError(f"no stable {repo} release has a .deb for {request['arch']}")
    return {"resolver": "github-release", "repo": repo, "asset_pattern": pattern, "channel": "stable",
            "approved_hosts": hosts, "homepage": f"https://github.com/{repo}"}


def probe(request, runner=None, http=None):
    """Work out a source configuration for a user-supplied URL and verify the
    package identity it serves (reads only the package head)."""
    runner = runner or Runner()
    http = http or HttpClient()
    url = request["url"]
    comparer = debpkg.VersionComparer(runner)
    ctx = resolvers.ResolveContext(http=http, arch=request["arch"], debian_major=request["debian_major"],
                                   comparer=comparer, min_rollout=request.get("min_rollout", 1.0))
    host = urllib.parse.urlsplit(url).hostname or ""
    if host.lower() == "github.com":
        source = _github_source(url, request, http, ctx)
    else:
        source = {"resolver": "direct-deb", "url": url, "pinned": False,
                  "approved_hosts": sorted(set(request["allowed_hosts"]) | {host.lower()})}
    release = resolvers.resolve(source, ctx)
    final, head = http.peek(release.url, source["approved_hosts"], resolvers.PEEK_BYTES)
    if not debpkg.looks_like_deb(head):
        raise ResolveError(
            f"{redact(url)} does not serve a Debian package (it looks like a web page)",
            hint="wardctl cannot reliably find the newest release on arbitrary pages. Provide a direct "
                 ".deb URL (ideally a vendor 'latest' endpoint), an official GitHub repository URL, or ask "
                 "for a maintained adapter for this vendor.")
    with tempfile.TemporaryDirectory(prefix="probe-") as work:
        path = os.path.join(work, "head.deb")
        with open(path, "wb") as fh:
            fh.write(head)
        info = debpkg.inspect_deb(runner, path)
    if not debpkg.arch_compatible(info.arch, request["arch"]):
        raise VerificationError(f"{redact(url)} serves {info.package} for {info.arch}; this system is "
                                f"{request['arch']}. Refusing to register an incompatible package.")
    return {"ok": True, "source": source, "release": release.to_dict(), "control": info.__dict__,
            "final_url": redact(final), "log": http.log}


def handle(request, runner=None, http=None):
    task = request.get("task", "prepare")
    if task == "prepare":
        return prepare(request, runner, http)
    if task == "probe":
        return probe(request, runner, http)
    raise WardctlError(f"unknown worker task {task!r}")


def main():
    try:
        request = json.loads(sys.stdin.read())
        result = handle(request)
    except WardctlError as exc:
        result = {"ok": False, "error": str(exc), "hint": exc.hint, "type": type(exc).__name__}
    except Exception as exc:  # report, never crash silently
        result = {"ok": False, "error": f"{type(exc).__name__}: {exc}", "hint": None, "type": "internal"}
    sys.stdout.write(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
