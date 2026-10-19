# wardctl

`wardctl` installs and updates specified software on Debian. It uses APT wherever APT
can manage an application. For applications no configured APT repository
supplies, it checks the vendor's official release source, verifies the package,
and installs it through `apt-get` so dependencies are resolved.

- **Tested platform:** Debian 13 (trixie), amd64. Other systems are detected
  and refused for install/update operations. Read-only commands still work.
- **Requirements:** Python 3.11+ (standard library only, no pip packages),
  `apt`, `dpkg`, `gpgv`, and `sudo`. A standard Debian 13 install includes
  all of them. `flatpak` is optional.
- **No AI service, account or API key** is used.

## Install

```sh
git clone … wardctl && cd wardctl      # or unpack the source tree
sudo ./install.sh
```

This installs wardctl's own files and nothing else:

| Path | Contents |
|---|---|
| `/usr/local/bin/wardctl` | launcher (`#!/usr/bin/python3 -I`) |
| `/usr/local/lib/wardctl/wardctl/` | the Python package (root-owned, read-only) |
| `/usr/local/lib/wardctl/MANIFEST` | list of installed files, used by the uninstaller |
| `/usr/local/share/doc/wardctl/` | this README, `SOURCES.md`, the config example |

`install.sh` can be run from any directory and run again safely; it replaces
the previous copy atomically. It does not run `apt-get` or `pip`, does not
touch system Python, and does not create per-user state. `--prefix DIR`
installs somewhere else.

At runtime wardctl also uses `/var/cache/wardctl/` (root-owned staging for
verified `.deb` files) and the lock file `/run/wardctl.lock`.

## First run

Run this as your normal user, without sudo:

```sh
wardctl init
```

`init` creates `~/.wardctl/` and runs **read-only discovery**:

- It reads the dpkg database (installed packages and versions) and APT's
  policy data (which enabled repository, if any, offers each package).
- It starts tracking the known applications it finds installed. Nothing is
  installed, upgraded or reinstalled.
- It lists other installed third-party applications as candidates, so you can
  decide whether to track them. Ordinary OS packages and libraries are left
  out of this list.
- It saves the inventory and the apps whose update source is unresolved.

`wardctl discover` repeats the scan later. It adds newly found apps and
never overwrites registrations you have edited.

## Everyday commands

```sh
wardctl                         # short status and how to update
wardctl status                  # installed versions, how each app is managed (offline)
wardctl list [--all]            # tracked apps (--all: also known-but-untracked)
wardctl check                   # look for updates; installs nothing; exit 10 if any
sudo wardctl check --refresh    # run apt-get update first, then check

sudo wardctl update             # the normal update run (see below)
wardctl update                  # same; re-runs itself with sudo
wardctl update --dry-run        # show the full plan; change nothing
sudo wardctl update obsidian    # only this app and the dependencies it needs
sudo wardctl update --apt-only  # only apt-get update + apt-get upgrade
sudo wardctl update --apps-only # only tracked apps, no system-wide upgrade
sudo wardctl update --yes       # noninteractive (see "Noninteractive runs")

wardctl doctor                  # check configuration, permissions, locks, tools
```

### What `update` does

1. **`apt-get update --error-on=any`**. If any repository fails to refresh,
   the run stops before anything is upgraded or installed (exit 1).
2. **`apt-get upgrade`**: a normal upgrade, never `full-upgrade` or
   `dist-upgrade`, no `autoremove`, nothing forced. Held packages are
   respected. Packages APT keeps back are reported and are not forced.
   `--full-upgrade` opts in to `apt-get full-upgrade` for one run.
3. wardctl **re-reads the dpkg database**, then evaluates each tracked app:
   - **Managed by APT** (an enabled repository offers the package): it is
     updated only by APT. If APT fails, wardctl reports the failure and does
     **not** fall back to a website download.
   - **Direct source** (no repository supplies it): the latest compatible
     release is resolved from the configured official source and compared
     with `dpkg --compare-versions`. If it is newer, the package is
     downloaded, verified, and installed with
     `apt-get install /var/cache/wardctl/staging/…/pkg.deb`.
   - **Flatpak**: `flatpak update --user|--system APP`. User installations
     are updated as you, not as root.
4. A summary table and exit code. wardctl never reboots. It tells you when
   `/run/reboot-required` exists.

`update APP` skips the system-wide upgrade. It runs
`apt-get install --only-upgrade` for that app's packages, or does the
direct-source update for that app alone.

### Dry run

`wardctl update --dry-run` does not need root, installs nothing, does not
modify APT metadata or repositories, and writes no wardctl state. It uses
the APT metadata from the last refresh. To build the plan it may:

- fetch release metadata over HTTPS (GitHub API, vendor manifests);
- for sources without version metadata (a "latest" `.deb` endpoint or a
  GitHub asset), download the **first 4 MB** of the package to a temporary
  directory and read its control data. The temporary file is deleted.

### Noninteractive runs

Without `--yes`, APT shows its normal prompts and wardctl asks before each
direct-source install. If stdin is not a terminal and `--yes` was not given,
the run refuses to start rather than hang.

With `--yes`, APT runs with `-y`, `DEBIAN_FRONTEND=noninteractive`, and
`NEEDRESTART_MODE=l`. Configuration-file questions are answered by
`settings.conffile_policy`:

- `keep-old` (the default) keeps your modified configuration files
  (`--force-confdef --force-confold`);
- `use-new` installs the package maintainer's version
  (`--force-confdef --force-confnew`).

### Exit codes

| Code | Meaning |
|---|---|
| 0 | success, nothing pending |
| 1 | fatal failure (for example, the APT refresh failed or the command was refused) |
| 2 | usage error |
| 10 | `check`: updates are available |
| 20 | partial failure: some steps succeeded, at least one failed (for `check`, some sources could not be checked) |
| 75 | busy: another wardctl run, or another APT/dpkg process holds a lock |
| 78 | configuration malformed or unsafe; the file was left untouched for you to repair |

## Registering versus installing

- **Registering** (`add`) records an app and its update source in
  `~/.wardctl/config.json`. It installs nothing.
- **Installing** (`install`) installs the app on your explicit request and
  then tracks it.
- **Removing** (`remove`) stops tracking an app. It does **not** uninstall the
  software.

```sh
wardctl add veracrypt                          # a built-in app, by id
wardctl add --package foo-app                  # an installed package; APT only until a source is added
wardctl add --url https://vendor.example/linux/latest/app_amd64.deb
wardctl add --url https://github.com/OWNER/REPO [--asset-pattern 'app_[0-9.]+_{arch}\.deb']
wardctl add --url https://proton.me/pass/download   # mapped to its maintained adapter
wardctl add --url https://vendor.example/latest --allow-host cdn.vendor.example

sudo wardctl install veracrypt
sudo wardctl install --url https://vendor.example/linux/latest/app_amd64.deb
sudo wardctl install discord --deb             # Discord's official .deb instead of its Flatpak
wardctl remove foo-app
```

When you add a source, wardctl reads the package's control data and saves
the verified identity: package name and architecture. Later downloads must
match that identity. A legitimate rename needs an explicit change:
`wardctl set APP --package NEWNAME`.

A URL that contains the release version (for example `app_2.1.deb`) is
recorded as **pinned**. wardctl warns that a pinned URL will never reveal
newer releases. Use `--endpoint` or `--pinned` to state this explicitly.

### Supplying a download page

An arbitrary download page cannot reliably reveal the newest package. If a
URL serves HTML rather than a `.deb`, wardctl says so and asks for one of:

- a direct `.deb` URL, preferably a vendor "latest" endpoint;
- an official GitHub repository;
- a maintained adapter.

It never picks the "numerically largest" link on a page. Built-in adapters
exist for the pages listed in [docs/SOURCES.md](docs/SOURCES.md). The
`html-link` resolver is available for vendor pages where exactly one link
matches a maintained pattern.

## How APT preference works

wardctl re-checks APT availability for every app on **every run**:

- A version counts as repository-provided only when `apt-cache policy` lists
  it from a real repository. The `/var/lib/dpkg/status` entry only shows
  that the package is installed, so it does not count.
- If a repository offers the package, APT manages it. This is how an app
  installed from a downloaded `.deb` switches to APT automatically once its
  installer adds a vendor repository. ChatGPT's `.deb` does this.
- If the installed version is **newer** than every repository version,
  wardctl reports `installed newer`. It never downgrades the package and
  does not call this an APT update. If the app has a direct source, that
  source is checked instead.
- Held packages (`apt-mark hold`) are never changed. This includes
  direct-source updates, unless you explicitly run
  `wardctl set APP --allow-held-update yes`.
- `wardctl set APP --policy direct-only` deliberately overrides APT for one
  app. wardctl warns what this means: you lose APT's signed-repository
  verification for that app, and `apt-get upgrade` may still replace it with
  a newer repository version. The other policies are `prefer-apt` (the
  default), `apt-only`, and `check-only`. `check-only` reports updates, and
  wardctl never installs them itself. The system-wide `apt-get upgrade`
  still upgrades APT-managed packages; use `apt-mark hold` to stop that.

wardctl **does not create, edit or duplicate APT repositories**. Vendor
repositories (Spotify, Sublime Text, Claude, VS Code, …) are used only when
you have already configured them.

## Provenance: what can and cannot be known

The dpkg database records what is installed and at which version. It does
**not** record whether a package came from a repository or from a downloaded
`.deb`, and it does not record the URL. wardctl therefore stores
`install_origin: "unknown"` for discovered apps. It records `"wardctl"` only
for installs it performed itself.

A package's `Homepage` field is shown as a hint. It is never used as a
download source. When no verified resolver exists for an app, wardctl marks
it **unresolved** and asks you for a source.

## Why some checks download part of a package

Some sources publish a version number: GitHub release metadata, or Proton's
`version.json`. Others are a fixed "latest" URL, or a GitHub asset whose tag
differs from the Debian version (VeraCrypt's tag `VeraCrypt_1.26.29` versus
package version `1.26.29-1~deb13-1`).

For those sources, the Debian control data is the only reliable version.
wardctl reads only the head of the file, which `dpkg-deb` can parse.
HTTP `ETag`/`Last-Modified` values are cache validators. They are never
treated as version numbers or as proof of authenticity.

## Verification

Before any direct-source install, wardctl:

1. downloads over HTTPS with certificate validation. The initial URL and
   every redirect must be HTTPS on an approved host, with no HTTPS→HTTP hops,
   no credentials and no unusual ports. GitHub's asset hosts
   (`release-assets.githubusercontent.com`, `objects.githubusercontent.com`)
   are approved for GitHub sources. Downloads have timeouts, bounded retries
   and a size limit (`settings.max_download_mb`). Signed CDN query strings are
   redacted from output.
2. checks vendor-published checksums: the Proton manifest's SHA-512, or
   GitHub's asset SHA-256 digest. It verifies OpenPGP signatures with `gpgv`
   against keys bundled with wardctl (VeraCrypt).
3. rejects anything that is not a Debian package, such as an HTML page served
   under a `.deb` name.
4. reads `Package`, `Version` and `Architecture` with `dpkg-deb`, enforces the
   registered identity and the system architecture, and refuses equal or
   older versions.
5. copies the file into a root-owned staging directory, then re-hashes and
   re-verifies it there before running `apt-get install`. If the file changed
   after verification, it is rejected.

Checksums wardctl computes itself only show that the file did not change
after download. They do not prove who published it, and wardctl does not
claim they do. Signature checking is never weakened, and
`--allow-unauthenticated` is never used.

## Privileges and per-user state

- Read-only commands (`status`, `list`, `check`, `doctor`, `--dry-run`) run as
  you, unprivileged.
- `update` and `install` need root. Run them with `sudo`, or let wardctl
  re-run itself through `sudo`. It does this only from a root-owned
  installation, never from a user-writable checkout.
- Under sudo, the invoking user is taken from `SUDO_UID`. It is validated
  against the account database, and it must match `SUDO_USER`. Your home
  directory comes from the account database, never from `$HOME`. State is
  therefore never written to `/root` by mistake.
- As root, wardctl reads and writes `~/.wardctl` with **your** uid, gid
  and groups, so files stay owned by you. All network and download handling,
  and parsing of untrusted metadata, happens in a child process that has
  fully dropped to your account. Root only runs fixed system commands
  (`apt-get`, `dpkg`, `gpgv`, `flatpak --system`) and copies the verified
  package into its own staging directory.
- The configuration never contains commands, hooks, plugins or executable
  paths. Unknown keys are rejected.
- **Direct root** (logged in as root, no `SUDO_UID`) uses root's own profile,
  `/root/.wardctl`. wardctl never guesses a desktop user.
- Self-elevation requires the launcher, the package directory, and every
  parent directory to be root-owned and not group- or world-writable. An
  older Debian layout with `/usr/local` as `root:staff` 2775 fails this
  check. In that case, install with `--prefix /opt/wardctl` or run
  `sudo wardctl` yourself.

**Threat model, stated plainly.** These measures stop root from writing your
state to the wrong place. They stop root from following planted symlinks, from
running anything named in a config file, and from installing a file that
changed after it was verified. They do not make a source you register
trustworthy. Installing a `.deb` runs its maintainer scripts as root. Any
program running as your user can edit `~/.wardctl/config.json`, just as it
could edit your shell profile. Review `wardctl list` before running
`sudo wardctl update` on a machine you suspect is compromised.

### Files in `~/.wardctl/`

| File | Purpose |
|---|---|
| `config.json` | Your registrations and settings: versioned schema, validated on every load, written atomically with mode 0600. A malformed file causes a repairable error and is never overwritten. Old schemas are migrated with a backup (`config.json.bak-schema-N`). |
| `state.json` | Observations: discovery inventory, candidates, last check and update results. It can be regenerated. A corrupt copy is moved to `state.json.corrupt`. |
| `cache/staging/` | Temporary download area (mode 0700). |
| `logs/wardctl.log` | Run log, rotated at 2 MB. |
| `lock` | Per-user lock. |

Installed versions are always re-read from the dpkg database. Cached
versions are never treated as authoritative. Symlinks, wrong ownership and
group- or world-writable state paths are refused.

See [examples/config.example.json](examples/config.example.json) for each
field: stable `id`, `display_name`, real Debian `packages`, `source.resolver`
and parameters, `approved_hosts`, `channel`, `architectures`,
`update_policy`, `verification` status, and `provenance`, which separates
`user_supplied` fields from `inferred` ones.

### Locks

wardctl takes a per-user lock and, for system changes, `/run/wardctl.lock`.
It checks APT/dpkg locks before starting (exit 75 if they are busy, with the
holding PID), and passes `DPkg::Lock::Timeout` so `apt-get` waits briefly
instead of failing. It never deletes APT lock files and never stops package
manager processes.

## Built-in applications

Known apps are tracked automatically **only when found installed**. Run
`wardctl list --all` to see all of them. Details and verification evidence
are in [docs/SOURCES.md](docs/SOURCES.md).

| App | How it is updated |
|---|---|
| suckless-tools, KeePassXC, Remmina (+RDP/VNC plugins), Nextcloud Desktop, Okular, qBittorrent | Debian archive via APT |
| Spotify, Sublime Text, Claude Desktop, VS Code | vendor APT repository (must already be configured) |
| ChatGPT | APT (its `.deb` installs OpenAI's repository); official `latest` `.deb` for first install |
| Obsidian | GitHub `obsidianmd/obsidian-releases` stable releases |
| VeraCrypt | GitHub `veracrypt/VeraCrypt` Debian 13 asset, OpenPGP-signature verified |
| Proton Mail, Proton Pass, Proton Authenticator | Proton's official `version.json` manifests, SHA-512 verified |
| Discord | existing user Flatpak; Discord's official `.deb` via `install discord --deb` |
| Nextcloud Talk | existing Flatpak only; **no verified `.deb` source (pending)** |
| Proton Drive | **unsupported**: standalone executable; detected, never downloaded or replaced |
| Private Internet Access | **unsupported**: `.run` installer; wardctl does not run installers |

## Uninstall

```sh
sudo ./uninstall.sh                  # remove the program; keep ~/.wardctl
sudo ./uninstall.sh --purge-config   # also remove the invoking user's ~/.wardctl
```

The uninstaller removes only the files listed in wardctl's manifest, plus
`/var/cache/wardctl` and its lock file. It never uninstalls tracked
applications, never removes APT repositories or keys, and never removes
shared dependencies.

`--purge-config` resolves the invoking user the same way `wardctl` does:
validated `SUDO_UID` and the account database, or root's own home for direct
root. It removes exactly one directory, `<home>/.wardctl`, and refuses
symlinks and directories owned by anyone else. It uses no wildcards and
touches no other users.

## Development and tests

```sh
python3 -m unittest discover -s tests -v
```

The tests use temporary home directories, fixture HTTP responses, and a
simulated dpkg/APT system. Only read-only tools run for real:
`dpkg --compare-versions`, plus `dpkg-deb` and `gpgv` on files created in
temporary directories. No test installs software, changes APT state, or
touches `~/.wardctl`. `install.sh`/`uninstall.sh` are tested unprivileged
against a temporary prefix.

Code layout:

| Module | Role |
|---|---|
| `cli.py` | commands, elevation |
| `engine.py` | evaluation, update pipeline, verified install |
| `apt.py` | APT policy, simulation, commands |
| `debpkg.py` | dpkg queries, version comparison, `.deb` inspection |
| `resolvers.py` | official-source resolvers |
| `netfetch.py` | HTTPS client |
| `worker.py` | unprivileged preparation |
| `identity.py`, `privilege.py` | user resolution, privilege boundary |
| `config.py`, `fsutil.py`, `locks.py` | state, safe files, locks |
| `catalog.py` | built-in apps |
| `discovery.py` | read-only inventory |
| `flatpak.py` | optional Flatpak support |
