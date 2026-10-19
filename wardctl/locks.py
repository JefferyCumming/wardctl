"""wardctl's own locks, plus a read-only probe of APT/dpkg locks.

wardctl never deletes APT/dpkg lock files and never signals the process
holding them; it reports the holder and stops (or lets apt-get wait, see
apt.LOCK_TIMEOUT).
"""

import fcntl
import os
import stat
import struct

from wardctl.errors import LockBusy, UnsafePathError

SYSTEM_LOCK = "/run/wardctl.lock"
APT_LOCKS = ("/var/lib/dpkg/lock-frontend", "/var/lib/dpkg/lock",
             "/var/lib/apt/lists/lock", "/var/cache/apt/archives/lock")


class FileLock:
    def __init__(self, path, owner_uid, description):
        self.path = path
        self.owner_uid = owner_uid
        self.description = description
        self.fd = None

    def acquire(self):
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != self.owner_uid:
            os.close(fd)
            raise UnsafePathError(f"lock file {self.path} has unexpected type or owner")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            raise LockBusy(f"{self.description} is already running (lock {self.path})",
                           hint="Wait for the other run to finish, then retry.")
        os.ftruncate(fd, 0)
        os.write(fd, f"{os.getpid()}\n".encode())
        self.fd = fd
        return self

    def release(self):
        if self.fd is not None:
            fcntl.flock(self.fd, fcntl.LOCK_UN)
            os.close(self.fd)
            self.fd = None

    def __enter__(self):
        return self.acquire()

    def __exit__(self, *exc):
        self.release()


def apt_lock_holder(paths=APT_LOCKS):
    """Return (path, pid) of a process holding an APT/dpkg lock, or None.
    Uses F_GETLK, which inspects the lock without taking it."""
    for path in paths:
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError:
            continue
        try:
            # struct flock: short l_type, short l_whence, off_t l_start, off_t l_len, pid_t l_pid
            fmt = "hhqqi"
            probe = struct.pack(fmt, fcntl.F_WRLCK, os.SEEK_SET, 0, 0, 0)
            res = fcntl.fcntl(fd, fcntl.F_GETLK, probe)
            l_type, _, _, _, pid = struct.unpack(fmt, res[:struct.calcsize(fmt)])
            if l_type != fcntl.F_UNLCK:
                return path, pid
        except OSError:
            continue
        finally:
            os.close(fd)
    return None


def process_name(pid):
    try:
        with open(f"/proc/{pid}/comm", encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return "unknown"
