# Built-in sources and their verification

All entries were checked on **2026-10-18** against Debian 13 (trixie) amd64.
"Verified" means the release mechanism was traced to the vendor's own
documentation or source code and observed live; it does not mean that wardctl
has performed a real installation or update with it (see "Limits" below).

Re-verify an entry before changing it. Old URLs, package names, keys and
release patterns from earlier scripts are hints, not evidence.

## Direct (non-APT) sources

| App | Resolver | Official source | Evidence | Integrity |
|---|---|---|---|---|
| Obsidian | `github-release` | `obsidianmd/obsidian-releases`, asset `obsidian_<ver>_amd64.deb` | <https://obsidian.md/download> links its `.deb` to this repository's releases. Latest stable seen: v1.14.4. Some releases (e.g. v1.13.8) ship no `.deb`; the resolver then uses the newest release that does and says so. | GitHub API asset SHA-256 digest (transfer integrity only; Obsidian publishes no signature). |
| VeraCrypt | `github-release` | `veracrypt/VeraCrypt`, asset `veracrypt-<ver>-Debian-13-amd64.deb` + `.sig` | <https://veracrypt.io/en/Downloads.html> links the Debian 13 build to these releases. Package inspected: `veracrypt` `1.26.29-1~deb13-1` `amd64`. | OpenPGP signature verified with `gpgv` against the bundled key `wardctl/data/keys/veracrypt.gpg`, fingerprint `5069A233D55A0EEB174A5FC3821ACD02680D16DE`, which matches the fingerprint printed on the official Downloads page (key file fetched from `https://amcrypto.jp/VeraCrypt/VeraCrypt_PGP_public_key.asc`). The 1.26.29 Debian 13 `.deb` signature verified successfully. |
| Proton Mail | `vendor-json` (`proton-version-json`) | `https://proton.me/download/mail/linux/version.json` | URL constructed by Proton's desktop updater: `ProtonMail/WebClients` `applications/inbox-desktop/src/update/update.ts`. Channels seen: Alpha, EarlyAccess, Stable. Package name `proton-mail` (file name `ProtonMail-desktop-beta.deb`). | Vendor-published SHA-512. |
| Proton Pass | `vendor-json` | `https://proton.me/download/PassDesktop/linux/x64/version.json` | Same `PassDesktop/{platform}/{arch}/version.json` layout used by `applications/pass-desktop/src/lib/updater` (the in-app updater itself only runs on macOS/Windows; the Linux manifest was observed live with the same schema). Channels: Stable, Beta; `RolloutPercentage` honoured. | Vendor-published SHA-512. |
| Proton Authenticator | `vendor-json` | `https://proton.me/download/authenticator/linux/version.json` | URL in `applications/authenticator/src/lib/tauri/update.ts` (`metadataUrl('linux')`). | Vendor-published SHA-512. |
| ChatGPT | APT preferred; `direct-deb` bootstrap | `https://persistent.oaistatic.com/codex-app-prod/linux/deb/latest/chatgpt_amd64.deb` | <https://learn.chatgpt.com/docs/linux/linux-app.md>: Debian 13 x64 supported; installing the `.deb` configures OpenAI's signed APT repository; documented update path is APT. On the development machine `chatgpt` is already served by `persistent.oaistatic.com/codex-app-prod/linux/deb stable/main` so wardctl manages it through APT. | TLS only for the bootstrap download (no published checksum); identity checked with `dpkg-deb`. |
| Discord (`.deb` alternative) | `direct-deb` | `https://discord.com/api/download?platform=linux&format=deb` → `stable.dl2.discordapp.net` | Endpoint on discord.com observed redirecting to `.../apps/linux/1.0.162/discord-1.0.162.deb`; control data inspected: `discord` `1.0.162` `amd64`. Used only with `wardctl install discord --deb`. | TLS only; identity checked with `dpkg-deb`. |

Proton's download pages (`proton.me/*/download`) are rendered client-side and
contain no static download links, so no HTML scraping is used for them;
`wardctl add --url https://proton.me/mail/download` maps the page to the
maintained manifest adapter instead.

## APT-managed applications

Debian archive (`deb.debian.org`, origin `Debian`): `suckless-tools`,
`keepassxc`, `remmina` (+ `remmina-plugin-rdp`, `remmina-plugin-vnc`),
`nextcloud-desktop`, `okular`, `qbittorrent`.

Vendor repositories (wardctl never adds, edits or duplicates them; it only
uses repositories already configured): `spotify-client`
(repository.spotify.com), `sublime-text` (download.sublimetext.com),
`claude-desktop` (downloads.claude.ai), `code` (packages.microsoft.com),
`chatgpt` (persistent.oaistatic.com). On the development machine all five were
present in `/etc/apt/sources.list.d/` with `signed-by` keyrings.

## Unsupported or pending

| App | Status | Why / what is needed |
|---|---|---|
| Proton Drive | unsupported | Linux build is a standalone executable (detected at `/usr/local/bin/proton-drive`, not owned by dpkg). No verified standalone-executable adapter exists; wardctl never downloads or replaces it. Needs: an official version manifest and checksum/signature for the CLI. |
| Private Internet Access | unsupported | Distributed as a `.run` shell installer; wardctl does not execute installers. The download page lists several versions (3.7, 3.8, arm64, armhf), so a "latest" cannot be selected without guessing. Needs: a dedicated adapter with an official version endpoint and signature. |
| Nextcloud Talk | pending | No official `.deb` source verified. Tracked only if the Flatpak `com.nextcloud.talk` is installed (it was, as a user Flatpak, on the development machine). |
| Discord (Flatpak) | tracked | `com.discordapp.Discord` user Flatpak (Flathub-maintained packaging of Discord's build). Updated with `flatpak update --user` as the invoking user. |

## Limits

- No live installation or update was performed during development; install and
  update paths were exercised only with mocked package-manager commands.
- Live, read-only checks were run: `apt-cache policy`/`dpkg-query` on the real
  system, GitHub API and Proton manifests, ranged reads of the Obsidian and
  Discord packages, and a full download + `gpgv` verification of the VeraCrypt
  1.26.29 Debian 13 package (not installed).
