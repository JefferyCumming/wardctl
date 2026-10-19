"""Careful file handling for user-owned state.

All functions here must be called with the user's credentials (inside
privilege.as_user when running as root). They refuse symlinks and files or
directories owned by someone else, and write atomically.
"""

import errno
import os
import stat
import tempfile

from wardctl.errors import UnsafePathError

MAX_STATE_FILE = 8 * 1024 * 1024


def _check_owned(path, st, uid, kind):
    if st.st_uid != uid:
        raise UnsafePathError(
            f"{path} is owned by uid {st.st_uid}, expected uid {uid}",
            hint="Fix ownership (for example with chown) or move the file away; "
                 "wardctl will not use state owned by another account.")
    if st.st_mode & 0o022:
        raise UnsafePathError(f"{kind} {path} is writable by group or others",
                              hint=f"Run: chmod go-w {path}")


def ensure_private_dir(path, uid, mode=0o700):
    """Create (or validate) a directory that must be a real directory owned
    by `uid`. Never follows a symlink at `path`."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        try:
            os.mkdir(path, mode)
        except FileExistsError:
            pass
        st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        raise UnsafePathError(f"{path} is a symbolic link; refusing to use it",
                              hint="Replace it with a real directory.")
    if not stat.S_ISDIR(st.st_mode):
        raise UnsafePathError(f"{path} exists and is not a directory")
    _check_owned(path, st, uid, "directory")
    return path


def check_home(home, uid):
    """The home directory itself may be a symlink (e.g. /home -> /data/home)
    but its target must be a directory owned by the user (or root for /root)."""
    try:
        st = os.stat(home)
    except OSError as exc:
        raise UnsafePathError(f"home directory {home} is not accessible: {exc.strerror}")
    if not stat.S_ISDIR(st.st_mode):
        raise UnsafePathError(f"home directory {home} is not a directory")
    if st.st_uid not in (uid, 0):
        raise UnsafePathError(f"home directory {home} is owned by uid {st.st_uid}, not {uid}")
    if st.st_mode & 0o002:
        raise UnsafePathError(f"home directory {home} is world-writable")


def read_private(path, uid, max_bytes=MAX_STATE_FILE):
    """Read a user-owned regular file without following symlinks.
    Returns None if it does not exist."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise UnsafePathError(f"{path} is a symbolic link; refusing to read it")
        raise UnsafePathError(f"cannot open {path}: {exc.strerror}")
    with os.fdopen(fd, "rb") as fh:
        st = os.fstat(fh.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise UnsafePathError(f"{path} is not a regular file")
        _check_owned(path, st, uid, "file")
        data = fh.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise UnsafePathError(f"{path} is larger than {max_bytes} bytes")
    return data


def atomic_write(path, data, mode=0o600):
    """Write `data` (bytes) to `path` via a temporary file in the same
    directory, fsync, then rename over the target."""
    directory = os.path.dirname(path)
    try:
        st = os.lstat(path)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            raise UnsafePathError(f"{path} is not a regular file; refusing to replace it")
    except FileNotFoundError:
        pass
    fd, tmp = tempfile.mkstemp(prefix="." + os.path.basename(path) + ".", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "wb") as fh:
            os.fchmod(fh.fileno(), mode)
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise
    dfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def append_private(path, uid, text, mode=0o600, max_bytes=2 * 1024 * 1024):
    """Append to a user-owned log file, rotating once it grows past max_bytes."""
    try:
        st = os.lstat(path)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            raise UnsafePathError(f"{path} is not a regular file")
        _check_owned(path, st, uid, "file")
        if st.st_size > max_bytes:
            os.replace(path, path + ".1")
    except FileNotFoundError:
        pass
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    with os.fdopen(fd, "a", encoding="utf-8") as fh:
        fh.write(text)
