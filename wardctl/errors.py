"""Exception types and documented process exit codes."""

EXIT_OK = 0            # success, nothing pending
EXIT_FATAL = 1         # fatal failure; nothing (further) was attempted
EXIT_USAGE = 2         # invalid command line
EXIT_UPDATES = 10      # `check`: updates are available
EXIT_PARTIAL = 20      # some steps succeeded, at least one failed
EXIT_BUSY = 75         # another wardctl run or APT/dpkg holds a lock
EXIT_CONFIG = 78       # configuration is malformed or unsafe; repair required


class WardctlError(Exception):
    """Base class for expected, user-facing failures."""

    exit_code = EXIT_FATAL

    def __init__(self, message, hint=None):
        super().__init__(message)
        self.hint = hint


class UnsupportedPlatform(WardctlError):
    pass


class IdentityError(WardctlError):
    pass


class UnsafePathError(WardctlError):
    exit_code = EXIT_CONFIG


class ConfigError(WardctlError):
    exit_code = EXIT_CONFIG


class LockBusy(WardctlError):
    exit_code = EXIT_BUSY


class FetchError(WardctlError):
    pass


class HostRejected(FetchError):
    pass


class ResolveError(WardctlError):
    pass


class VerificationError(WardctlError):
    pass


class CommandFailed(WardctlError):
    def __init__(self, argv, returncode, output="", hint=None):
        super().__init__(f"{argv[0]} exited with status {returncode}", hint)
        self.argv = list(argv)
        self.returncode = returncode
        self.output = output


class UserAbort(WardctlError):
    pass
