"""Built-in application catalog.

Every direct-download source below was checked against the vendor's current
official documentation or official source code on VERIFIED_ON (see
docs/SOURCES.md for the evidence). Entries whose release mechanism could not
be verified, or which need an installer type wardctl does not implement,
are marked unsupported/pending and are never downloaded or executed.

The catalog never creates APT repositories. Apps marked resolver "apt"
are updated only through repositories the user has already configured.
"""

import copy
import os

VERIFIED_ON = "2026-10-18"

GITHUB_HOSTS = ["api.github.com", "github.com", "release-assets.githubusercontent.com",
                "objects.githubusercontent.com"]


def _apt_app(app_id, name, packages, repo_note, homepage=None, vendor_repo=False):
    return {
        "id": app_id, "display_name": name, "kind": "deb", "packages": packages,
        "source": {"resolver": "apt", "approved_hosts": [],
                   **({"homepage": homepage} if homepage else {})},
        "architectures": [], "update_policy": "prefer-apt",
        "verification": {"status": "verified", "checked_on": VERIFIED_ON, "method": repo_note},
        "vendor_repository": vendor_repo,
    }


CATALOG = {
    # --- Debian archive packages -------------------------------------------
    "suckless-tools": _apt_app("suckless-tools", "suckless-tools (dmenu, slock, ...)", ["suckless-tools"],
                               "Debian 13 main archive"),
    "keepassxc": _apt_app("keepassxc", "KeePassXC", ["keepassxc"], "Debian 13 main archive"),
    "remmina": _apt_app("remmina", "Remmina", ["remmina", "remmina-plugin-rdp", "remmina-plugin-vnc"],
                        "Debian 13 main archive"),
    "nextcloud-desktop": _apt_app("nextcloud-desktop", "Nextcloud Desktop", ["nextcloud-desktop"],
                                  "Debian 13 main archive"),
    "okular": _apt_app("okular", "Okular", ["okular"], "Debian 13 main archive"),
    "qbittorrent": _apt_app("qbittorrent", "qBittorrent", ["qbittorrent"], "Debian 13 main archive"),

    # --- Vendor APT repositories (user-configured; wardctl never adds them)
    "spotify": _apt_app("spotify", "Spotify", ["spotify-client"],
                        "vendor APT repository repository.spotify.com (configure per vendor instructions)",
                        "https://www.spotify.com/download/linux/", vendor_repo=True),
    "sublime-text": _apt_app("sublime-text", "Sublime Text", ["sublime-text"],
                             "vendor APT repository download.sublimetext.com (configure per vendor instructions)",
                             "https://www.sublimetext.com/docs/linux_repositories.html", vendor_repo=True),
    "claude-desktop": _apt_app("claude-desktop", "Claude Desktop", ["claude-desktop"],
                               "vendor APT repository downloads.claude.ai (configure per vendor instructions)",
                               "https://claude.ai/download", vendor_repo=True),
    "code": _apt_app("code", "Visual Studio Code", ["code"],
                     "vendor APT repository packages.microsoft.com (configure per vendor instructions)",
                     "https://code.visualstudio.com/docs/setup/linux", vendor_repo=True),

    # --- Direct official sources -------------------------------------------
    "chatgpt": {
        "id": "chatgpt", "display_name": "ChatGPT", "kind": "deb", "packages": ["chatgpt"],
        "source": {
            "resolver": "direct-deb", "pinned": False,
            "url": "https://persistent.oaistatic.com/codex-app-prod/linux/deb/latest/chatgpt_{arch}.deb",
            "approved_hosts": ["persistent.oaistatic.com"],
            "homepage": "https://learn.chatgpt.com/docs/linux/linux-app.md",
        },
        "architectures": ["amd64"], "update_policy": "prefer-apt",
        "verification": {
            "status": "verified", "checked_on": VERIFIED_ON,
            "method": "OpenAI Linux app documentation lists this 'latest' .deb URL for Debian 13 x64; "
                      "installing it configures OpenAI's signed APT repository, after which APT manages updates.",
            "integrity": "TLS only; no published checksum. Package identity checked with dpkg-deb.",
        },
    },
    "obsidian": {
        "id": "obsidian", "display_name": "Obsidian", "kind": "deb", "packages": ["obsidian"],
        "source": {
            "resolver": "github-release", "repo": "obsidianmd/obsidian-releases",
            "asset_pattern": r"obsidian_[0-9][0-9.]*_{arch}\.deb", "channel": "stable",
            "approved_hosts": GITHUB_HOSTS, "homepage": "https://obsidian.md/download",
        },
        "architectures": ["amd64"], "update_policy": "prefer-apt",
        "verification": {
            "status": "verified", "checked_on": VERIFIED_ON,
            "method": "obsidian.md/download links the .deb from GitHub obsidianmd/obsidian-releases.",
            "integrity": "GitHub API asset SHA-256 digest (transfer integrity, not a publisher signature).",
        },
    },
    "veracrypt": {
        "id": "veracrypt", "display_name": "VeraCrypt", "kind": "deb", "packages": ["veracrypt"],
        "source": {
            "resolver": "github-release", "repo": "veracrypt/VeraCrypt",
            "asset_pattern": r"veracrypt-[0-9][0-9.]*-Debian-{debian_major}-{arch}\.deb",
            "tag_pattern": r"VeraCrypt_[0-9][0-9.]*", "channel": "stable",
            "signature": {"suffix": ".sig", "keyring": "veracrypt"},
            "approved_hosts": GITHUB_HOSTS, "homepage": "https://veracrypt.io/en/Downloads.html",
        },
        "architectures": ["amd64"], "update_policy": "prefer-apt",
        "verification": {
            "status": "verified", "checked_on": VERIFIED_ON,
            "method": "veracrypt.io Downloads page links the Debian 13 .deb from GitHub veracrypt/VeraCrypt releases.",
            "integrity": "OpenPGP signature (.sig) verified with gpgv against the bundled VeraCrypt key "
                         "5069A233D55A0EEB174A5FC3821ACD02680D16DE (fingerprint matches the official Downloads page).",
        },
    },
    "proton-mail": {
        "id": "proton-mail", "display_name": "Proton Mail", "kind": "deb", "packages": ["proton-mail"],
        "source": {
            "resolver": "vendor-json", "format": "proton-version-json", "channel": "Stable",
            "url": "https://proton.me/download/mail/linux/version.json",
            "approved_hosts": ["proton.me"], "homepage": "https://proton.me/mail/download",
        },
        "architectures": ["amd64"], "update_policy": "prefer-apt",
        "verification": {
            "status": "verified", "checked_on": VERIFIED_ON,
            "method": "Manifest URL taken from Proton's official desktop app source "
                      "(ProtonMail/WebClients applications/inbox-desktop/src/update/update.ts).",
            "integrity": "SHA-512 checksum published in the vendor manifest.",
        },
    },
    "proton-pass": {
        "id": "proton-pass", "display_name": "Proton Pass", "kind": "deb", "packages": ["proton-pass"],
        "source": {
            "resolver": "vendor-json", "format": "proton-version-json", "channel": "Stable",
            "url": "https://proton.me/download/PassDesktop/linux/x64/version.json",
            "approved_hosts": ["proton.me"], "homepage": "https://proton.me/pass/download",
        },
        "architectures": ["amd64"], "update_policy": "prefer-apt",
        "verification": {
            "status": "verified", "checked_on": VERIFIED_ON,
            "method": "Same PassDesktop/{platform}/{arch}/version.json layout used by Proton's official updater "
                      "(ProtonMail/WebClients applications/pass-desktop/src/lib/updater); Linux manifest observed live.",
            "integrity": "SHA-512 checksum published in the vendor manifest.",
        },
    },
    "proton-authenticator": {
        "id": "proton-authenticator", "display_name": "Proton Authenticator", "kind": "deb",
        "packages": ["proton-authenticator"],
        "source": {
            "resolver": "vendor-json", "format": "proton-version-json", "channel": "Stable",
            "url": "https://proton.me/download/authenticator/linux/version.json",
            "approved_hosts": ["proton.me"], "homepage": "https://proton.me/authenticator/download",
        },
        "architectures": ["amd64"], "update_policy": "prefer-apt",
        "verification": {
            "status": "verified", "checked_on": VERIFIED_ON,
            "method": "Manifest URL taken from Proton's official app source "
                      "(ProtonMail/WebClients applications/authenticator/src/lib/tauri/update.ts).",
            "integrity": "SHA-512 checksum published in the vendor manifest.",
        },
    },
    "discord": {
        "id": "discord", "display_name": "Discord", "kind": "flatpak", "packages": [],
        "flatpak": {"app_id": "com.discordapp.Discord", "installation": "user"},
        "alternatives": {
            "deb": {
                "packages": ["discord"],
                "source": {
                    "resolver": "direct-deb", "pinned": False,
                    "url": "https://discord.com/api/download?platform=linux&format=deb",
                    "approved_hosts": ["discord.com", "stable.dl2.discordapp.net"],
                    "homepage": "https://discord.com/download",
                },
            },
        },
        "source": {"resolver": "none", "approved_hosts": []},
        "architectures": ["amd64"], "update_policy": "prefer-apt",
        "verification": {
            "status": "verified", "checked_on": VERIFIED_ON,
            "method": "Existing install is the Flathub package (Flathub-maintained wrapper of Discord's build); "
                      "updated with flatpak. Discord's official .deb endpoint (discord.com/api/download, "
                      "redirecting to stable.dl2.discordapp.net, package 'discord') is available via "
                      "`wardctl install discord --deb`.",
        },
    },
    "nextcloud-talk": {
        "id": "nextcloud-talk", "display_name": "Nextcloud Talk", "kind": "flatpak", "packages": [],
        "flatpak": {"app_id": "com.nextcloud.talk", "installation": "user"},
        "source": {"resolver": "none", "approved_hosts": []},
        "architectures": [], "update_policy": "prefer-apt",
        "verification": {
            "status": "pending", "checked_on": VERIFIED_ON,
            "method": "Tracked only as an existing Flatpak. No official .deb source was verified; "
                      "supply one with `wardctl add nextcloud-talk --url ...` if Nextcloud publishes it.",
        },
    },
    "proton-drive": {
        "id": "proton-drive", "display_name": "Proton Drive (CLI)", "kind": "standalone", "packages": [],
        "standalone": {"probe_paths": ["/usr/local/bin/proton-drive"]},
        "source": {"resolver": "none", "approved_hosts": [], "homepage": "https://proton.me/drive/download"},
        "architectures": [], "update_policy": "check-only",
        "verification": {
            "status": "unsupported", "checked_on": VERIFIED_ON,
            "method": "Distributed as a standalone executable, not a .deb. wardctl has no verified "
                      "standalone-executable adapter; detection only, never downloaded or replaced.",
        },
    },
    "private-internet-access": {
        "id": "private-internet-access", "display_name": "Private Internet Access", "kind": "run-installer",
        "packages": [],
        "standalone": {"probe_paths": ["/opt/piavpn/bin/piactl"]},
        "source": {"resolver": "none", "approved_hosts": [],
                   "homepage": "https://www.privateinternetaccess.com/download/linux-vpn"},
        "architectures": [], "update_policy": "check-only",
        "verification": {
            "status": "unsupported", "checked_on": VERIFIED_ON,
            "method": "Distributed as a .run shell installer. wardctl does not execute .run installers; "
                      "the download page lists several versions, so no 'latest' can be chosen reliably.",
        },
    },
}

# Keys that exist only in the catalog and are not stored in config records.
CATALOG_ONLY_KEYS = ("alternatives", "vendor_repository")


def get(app_id):
    entry = CATALOG.get(app_id)
    return copy.deepcopy(entry) if entry else None


def match_page(url):
    """Map an official download page URL to a catalog app id, if known."""
    norm = url.rstrip("/").split("#")[0]
    for app_id, entry in CATALOG.items():
        home = (entry.get("source") or {}).get("homepage", "")
        if home and home.rstrip("/") == norm:
            return app_id
    return None


def to_record(entry, registered_by="catalog", today=None):
    rec = {k: copy.deepcopy(v) for k, v in entry.items() if k not in CATALOG_ONLY_KEYS}
    rec.setdefault("allow_held_update", False)
    rec["provenance"] = {
        "registered_by": registered_by,
        "catalog_verified_on": VERIFIED_ON,
        "install_origin": "unknown",
        "user_supplied": [],
        "inferred": [],
    }
    if today:
        rec["added_at"] = today
    return rec


def for_package(name):
    for app_id, entry in CATALOG.items():
        if name in entry.get("packages", []):
            return app_id
        alt = (entry.get("alternatives") or {}).get("deb")
        if alt and name in alt.get("packages", []):
            return app_id
    return None


def probe_exists(paths):
    """Existence check for non-package installs (never reads or runs them)."""
    return any(os.path.exists(p) for p in paths)


def for_flatpak(flatpak_id):
    for app_id, entry in CATALOG.items():
        if (entry.get("flatpak") or {}).get("app_id") == flatpak_id:
            return app_id
    return None
