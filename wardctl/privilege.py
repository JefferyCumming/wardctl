"""The privilege boundary.

When wardctl runs as root for an invoking user:
  * user-owned files are read and written inside `as_user()`, which switches
    the effective uid/gid/groups so the kernel applies the user's
    permissions and new files are owned by the user;
  * untrusted network data (metadata, downloads, .deb inspection) is handled
    by a child process that has fully dropped to the user (see worker.py);
  * only fixed, absolute system commands run with root privileges.
"""

import os
import stat
import sys
from contextlib import contextmanager

from wardctl import runner as R
from wardctl.errors import WardctlError

_os = os  # replaced in tests


@contextmanager
def as_user(identity):
    if not identity.drops_privileges:
        yield
        return
    saved_groups = _os.getgroups()
    old_umask = _os.umask(0o077)
    _os.setgroups(list(identity.groups))
    _os.setegid(identity.gid)
    _os.seteuid(identity.uid)
    try:
        yield
    finally:
        _os.seteuid(0)
        _os.setegid(0)
        _os.setgroups(saved_groups)
        _os.umask(old_umask)


def user_process_kwargs(identity):
    """subprocess keyword arguments that run a child fully as the user."""
    if not identity.drops_privileges:
        return {}
    return {"user": identity.uid, "group": identity.gid,
            "extra_groups": list(identity.groups), "umask": 0o077}


def user_env(identity, extra=None):
    env = R.base_env({"HOME": identity.home, "USER": identity.name,
                      "LOGNAME": identity.name})
    runtime = f"/run/user/{identity.uid}"
    if os.path.isdir(runtime):
        env["XDG_RUNTIME_DIR"] = runtime
        if os.path.exists(runtime + "/bus"):
            env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={runtime}/bus"
    if extra:
        env.update(extra)
    return env


def package_parent():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def is_trusted_path(path, lstat=os.lstat):
    """True if `path` and every parent directory is root-owned and not
    writable by group or others (sticky world-writable dirs are rejected)."""
    path = os.path.abspath(path)
    while True:
        try:
            st = lstat(path)
        except OSError:
            return False
        if stat.S_ISLNK(st.st_mode):
            try:
                target = os.path.realpath(path)
            except OSError:
                return False
            if not is_trusted_path(target, lstat):
                return False
        elif st.st_uid != 0 or st.st_mode & 0o022:
            return False
        parent = os.path.dirname(path)
        if parent == path:
            return True
        path = parent


def elevation_argv(argv, launcher=None):
    """The command that re-executes wardctl under sudo.

    Elevation is only offered from a root-owned installation: re-running a
    user-writable checkout as root would let user-editable code run as root.
    """
    launcher = launcher or os.path.realpath(sys.argv[0])
    pkg = package_parent()
    if not (os.path.isfile(launcher) and is_trusted_path(launcher) and is_trusted_path(pkg)):
        raise WardctlError(
            "this operation needs root privileges, and this copy of wardctl is not a "
            "root-owned installation, so it will not elevate itself.",
            hint="Install with ./install.sh and run `sudo wardctl ...`, or run this "
                 "checkout with sudo explicitly if you trust it.")
    if not os.access(R.SUDO, os.X_OK):
        raise WardctlError("sudo is not installed; run this command as root.")
    return [R.SUDO, "--", launcher, *argv]
