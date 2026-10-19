"""The single place where wardctl starts external programs.

Every command is an argument list with an absolute executable path; no shell
is ever involved. Tests substitute a fake runner.
"""

import os
import subprocess
from dataclasses import dataclass

APT_GET = "/usr/bin/apt-get"
APT_CACHE = "/usr/bin/apt-cache"
APT_MARK = "/usr/bin/apt-mark"
DPKG = "/usr/bin/dpkg"
DPKG_QUERY = "/usr/bin/dpkg-query"
DPKG_DEB = "/usr/bin/dpkg-deb"
FLATPAK = "/usr/bin/flatpak"
GPGV = "/usr/bin/gpgv"
SUDO = "/usr/bin/sudo"

SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


def base_env(extra=None):
    """A minimal, predictable environment for child processes."""
    env = {"PATH": SAFE_PATH, "LC_ALL": "C.UTF-8", "LANG": "C.UTF-8"}
    if extra:
        env.update(extra)
    return env


@dataclass
class Result:
    argv: list
    returncode: int
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self):
        return self.returncode == 0


class Runner:
    """Runs commands. `interactive=True` inherits the terminal so APT prompts
    and progress stay visible; otherwise output is captured."""

    def run(self, argv, *, interactive=False, env=None, input=None, cwd=None,
            user_kwargs=None, timeout=None):
        if not argv or not os.path.isabs(argv[0]):
            raise ValueError("commands must use an absolute executable path")
        kwargs = dict(env=env if env is not None else base_env(), cwd=cwd,
                      timeout=timeout, close_fds=True)
        if user_kwargs:
            kwargs.update(user_kwargs)
        if interactive:
            proc = subprocess.run(list(argv), **kwargs)
            return Result(list(argv), proc.returncode)
        proc = subprocess.run(list(argv), input=input, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              stdin=None if input is not None else subprocess.DEVNULL,
                              **kwargs)
        return Result(list(argv), proc.returncode, proc.stdout, proc.stderr)

    def exists(self, path):
        return os.access(path, os.X_OK)
