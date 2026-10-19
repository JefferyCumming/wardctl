"""Optional Flatpak support.

User installations are always queried and updated as the invoking user
(never as root, which would act on root's own user installation). System
installations are updated with root privileges.
"""

import os

from wardctl import runner as R
from wardctl.privilege import user_env, user_process_kwargs


def available(runner):
    return runner.exists(R.FLATPAK)


def _run_as(runner, identity, installation, argv, interactive=False):
    if installation == "user" or not identity.is_root_process:
        return runner.run(argv, interactive=interactive, env=user_env(identity),
                          user_kwargs=user_process_kwargs(identity), cwd=identity.home
                          if os.path.isdir(identity.home) else None)
    return runner.run(argv, interactive=interactive)


def list_installed(runner, identity):
    """Return {(app_id, installation): version} for installed Flatpak apps."""
    found = {}
    if not available(runner):
        return found
    for inst in ("user", "system"):
        res = _run_as(runner, identity, "user",
                      [R.FLATPAK, "list", "--app", f"--{inst}", "--columns=application,version"])
        if not res.ok:
            continue
        for line in res.stdout.splitlines():
            parts = line.split("\t")
            if parts and parts[0] and not parts[0].startswith("Application"):
                found[(parts[0].strip(), inst)] = parts[1].strip() if len(parts) > 1 else ""
    return found


def pending_updates(runner, identity, installation):
    """Application IDs with updates available (contacts the remotes)."""
    res = _run_as(runner, identity, installation,
                  [R.FLATPAK, "remote-ls", "--updates", "--app", f"--{installation}", "--columns=application"])
    if not res.ok:
        return None, (res.stderr or res.stdout).strip()
    return {line.strip() for line in res.stdout.splitlines() if line.strip()}, ""


def update(runner, identity, installation, app_id, yes):
    argv = [R.FLATPAK, "update", f"--{installation}"]
    if yes:
        argv += ["-y", "--noninteractive"]
    argv += ["--", app_id]
    return _run_as(runner, identity, installation, argv, interactive=True)
