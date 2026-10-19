"""Determine whose per-user state wardctl operates on.

Policy:
  * Normal user (euid != 0): that account, from the account database.
    $HOME is never trusted.
  * Root via sudo: SUDO_UID must be a decimal uid that exists in the account
    database; if SUDO_USER is present it must name the same account. The home
    directory comes from the account database.
  * Direct root (no SUDO_UID, or SUDO_UID=0): root's own profile
    (/root/.wardctl from the account database). No other user is ever
    guessed.
"""

import os
import pwd
from dataclasses import dataclass, field

from wardctl.errors import IdentityError

MODE_USER = "user"      # running as the target user, no privileges
MODE_SUDO = "sudo"      # running as root on behalf of an invoking user
MODE_ROOT = "root"      # running as root for root's own profile


@dataclass(frozen=True)
class Identity:
    uid: int
    gid: int
    name: str
    home: str
    mode: str
    groups: tuple = field(default=())

    @property
    def is_root_process(self):
        return self.mode in (MODE_SUDO, MODE_ROOT)

    @property
    def drops_privileges(self):
        """True when user-side work must be done with the user's credentials."""
        return self.mode == MODE_SUDO

    def describe(self):
        if self.mode == MODE_SUDO:
            return f"{self.name} (uid {self.uid}, via sudo)"
        if self.mode == MODE_ROOT:
            return "root (direct root execution: root's own profile)"
        return f"{self.name} (uid {self.uid})"


def _valid_home(pw):
    home = pw.pw_dir or ""
    if not os.path.isabs(home) or os.path.normpath(home) == "/":
        raise IdentityError(
            f"account {pw.pw_name!r} has no usable home directory ({home!r}) in the account database")
    return os.path.normpath(home)


def _from_pw(pw, mode, getgrouplist):
    try:
        groups = tuple(sorted(set(getgrouplist(pw.pw_name, pw.pw_gid))))
    except (OSError, KeyError):
        groups = (pw.pw_gid,)
    return Identity(uid=pw.pw_uid, gid=pw.pw_gid, name=pw.pw_name,
                    home=_valid_home(pw), mode=mode, groups=groups)


def resolve(env=None, euid=None, getpwuid=pwd.getpwuid, getgrouplist=os.getgrouplist):
    env = os.environ if env is None else env
    euid = os.geteuid() if euid is None else euid

    if euid != 0:
        try:
            pw = getpwuid(euid)
        except KeyError:
            raise IdentityError(f"uid {euid} is not in the account database")
        return _from_pw(pw, MODE_USER, getgrouplist)

    raw_uid = env.get("SUDO_UID")
    sudo_user = env.get("SUDO_USER")
    if raw_uid is None or raw_uid == "":
        if sudo_user:
            raise IdentityError("SUDO_USER is set but SUDO_UID is missing; refusing to guess the invoking user")
        return _from_pw(getpwuid(0), MODE_ROOT, getgrouplist)

    if not (raw_uid.isascii() and raw_uid.isdigit()) or len(raw_uid) > 10:
        raise IdentityError(f"SUDO_UID={raw_uid!r} is not a valid uid")
    uid = int(raw_uid)
    if uid == 0:
        return _from_pw(getpwuid(0), MODE_ROOT, getgrouplist)
    try:
        pw = getpwuid(uid)
    except KeyError:
        raise IdentityError(f"SUDO_UID={uid} does not exist in the account database")
    if sudo_user is not None and sudo_user != pw.pw_name:
        raise IdentityError(
            f"SUDO_USER={sudo_user!r} does not match uid {uid} ({pw.pw_name!r}); refusing to continue")
    return _from_pw(pw, MODE_SUDO, getgrouplist)
