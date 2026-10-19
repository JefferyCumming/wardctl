"""Checksum and signature verification.

A SHA-256 that wardctl computes itself only proves the file did not change
after download; it says nothing about who published it. Authenticity comes
from a vendor-published checksum fetched over HTTPS from the vendor, or (stronger)
an OpenPGP signature checked against a key bundled with wardctl.
"""

import hashlib
import hmac
import os
import tempfile

from wardctl import runner as R
from wardctl.errors import VerificationError

KEY_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "keys")


def keyring_path(name):
    if not name.isalnum():
        raise VerificationError(f"invalid keyring name {name!r}")
    path = os.path.join(KEY_DIR, name + ".gpg")
    if not os.path.isfile(path):
        raise VerificationError(f"bundled keyring {name!r} is missing from {KEY_DIR}")
    return path


def file_hashes(path):
    h256, h512 = hashlib.sha256(), hashlib.sha512()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h256.update(chunk)
            h512.update(chunk)
    return h256.hexdigest(), h512.hexdigest()


def check_checksums(expected, sha256, sha512):
    """Return a list of the algorithms that matched; raise on mismatch."""
    matched = []
    for algo, actual in (("sha256", sha256), ("sha512", sha512)):
        want = expected.get(algo)
        if want is None:
            continue
        if not hmac.compare_digest(want.lower(), actual.lower()):
            raise VerificationError(f"{algo.upper()} mismatch: published {want[:16]}…, downloaded {actual[:16]}…",
                                    hint="The download is corrupt or not the published file; nothing was installed.")
        matched.append(algo)
    return matched


def check_signature(runner, keyring, sig_path, data_path, user_kwargs=None):
    with tempfile.TemporaryDirectory(prefix="wardctl-gpg-") as home:
        res = runner.run([R.GPGV, "--keyring", keyring_path(keyring), "--", sig_path, data_path],
                         env=R.base_env({"GNUPGHOME": home}), user_kwargs=user_kwargs)
    if not res.ok:
        raise VerificationError(f"OpenPGP signature verification failed: {(res.stderr or '').strip()[-300:]}",
                                hint="The package was not installed.")
    return True
