"""Invoking-user resolution, privilege switching, unsafe paths, config
validation/migration and atomic state handling."""

import json
import os
import pwd
import stat
import unittest
from unittest import mock

from helpers import TempHomeCase, fake_pw, make_identity

from wardctl import config, fsutil, identity, privilege
from wardctl.errors import ConfigError, IdentityError, UnsafePathError


def pwdb(entries):
    def getpwuid(uid):
        if uid not in entries:
            raise KeyError(uid)
        return entries[uid]
    return getpwuid


ALICE = pwd.struct_passwd(("alice", "x", 1000, 1000, "", "/home/alice", "/bin/bash"))
BOB = pwd.struct_passwd(("bob", "x", 1001, 1001, "", "/home/bob", "/bin/bash"))
ROOT = pwd.struct_passwd(("root", "x", 0, 0, "", "/root", "/bin/bash"))
DB = pwdb({1000: ALICE, 1001: BOB, 0: ROOT})
GROUPS = lambda name, gid: [gid, 27]  # noqa: E731


class IdentityTests(unittest.TestCase):
    def resolve(self, env, euid):
        return identity.resolve(env=env, euid=euid, getpwuid=DB, getgrouplist=GROUPS)

    def test_normal_user_ignores_home_env(self):
        ident = self.resolve({"HOME": "/tmp/evil", "SUDO_UID": "1001"}, euid=1000)
        self.assertEqual((ident.name, ident.home, ident.mode), ("alice", "/home/alice", identity.MODE_USER))

    def test_sudo_uses_account_database_not_root_home(self):
        ident = self.resolve({"SUDO_UID": "1000", "SUDO_USER": "alice", "HOME": "/root"}, euid=0)
        self.assertEqual((ident.uid, ident.home, ident.mode), (1000, "/home/alice", identity.MODE_SUDO))
        self.assertTrue(ident.drops_privileges)
        self.assertEqual(ident.groups, (27, 1000))

    def test_sudo_user_mismatch_rejected(self):
        with self.assertRaises(IdentityError):
            self.resolve({"SUDO_UID": "1000", "SUDO_USER": "bob"}, euid=0)

    def test_invalid_sudo_uid_rejected(self):
        for bad in ("abc", "-1", "1000 ", "１０００", "99999999999"):
            with self.subTest(bad=bad), self.assertRaises(IdentityError):
                self.resolve({"SUDO_UID": bad}, euid=0)

    def test_unknown_sudo_uid_rejected(self):
        with self.assertRaises(IdentityError):
            self.resolve({"SUDO_UID": "4242"}, euid=0)

    def test_direct_root_uses_root_profile_never_guesses(self):
        ident = self.resolve({"HOME": "/home/alice"}, euid=0)
        self.assertEqual((ident.name, ident.home, ident.mode), ("root", "/root", identity.MODE_ROOT))
        self.assertFalse(ident.drops_privileges)
        self.assertEqual(self.resolve({"SUDO_UID": "0"}, euid=0).mode, identity.MODE_ROOT)

    def test_sudo_user_without_uid_rejected(self):
        with self.assertRaises(IdentityError):
            self.resolve({"SUDO_USER": "alice"}, euid=0)

    def test_unusable_home_rejected(self):
        db = pwdb({1000: pwd.struct_passwd(("alice", "x", 1000, 1000, "", "/", "/bin/sh"))})
        with self.assertRaises(IdentityError):
            identity.resolve(env={"SUDO_UID": "1000"}, euid=0, getpwuid=db, getgrouplist=GROUPS)


class AsUserTests(unittest.TestCase):
    def test_switches_and_restores_credentials(self):
        calls = []
        fake = mock.Mock()
        fake.getgroups.return_value = [0]
        fake.umask.return_value = 0o022
        for name in ("setgroups", "setegid", "seteuid"):
            getattr(fake, name).side_effect = lambda *a, n=name: calls.append((n, a))
        ident = identity.Identity(1000, 1000, "alice", "/home/alice", identity.MODE_SUDO, (27, 1000))
        with mock.patch.object(privilege, "_os", fake):
            with privilege.as_user(ident):
                calls.append(("body", ()))
            with self.assertRaises(RuntimeError), privilege.as_user(ident):
                raise RuntimeError("boom")
        first = calls[:6]
        self.assertEqual(first, [("setgroups", ([27, 1000],)), ("setegid", (1000,)), ("seteuid", (1000,)),
                                 ("body", ()), ("seteuid", (0,)), ("setegid", (0,))])
        self.assertEqual(calls[6], ("setgroups", ([0],)))
        self.assertEqual(calls[-3:], [("seteuid", (0,)), ("setegid", (0,)), ("setgroups", ([0],))])

    def test_noop_for_unprivileged_user(self):
        fake = mock.Mock()
        ident = identity.Identity(1000, 1000, "alice", "/home/alice", identity.MODE_USER)
        with mock.patch.object(privilege, "_os", fake), privilege.as_user(ident):
            pass
        fake.seteuid.assert_not_called()

    def test_worker_kwargs_drop_fully(self):
        ident = identity.Identity(1000, 1000, "alice", "/home/alice", identity.MODE_SUDO, (1000, 27))
        kw = privilege.user_process_kwargs(ident)
        self.assertEqual((kw["user"], kw["group"], kw["extra_groups"]), (1000, 1000, [1000, 27]))
        env = privilege.user_env(ident)
        self.assertEqual(env["HOME"], "/home/alice")
        self.assertNotIn("SUDO_UID", env)

    def test_elevation_refused_for_user_writable_checkout(self):
        from wardctl.errors import WardctlError
        with self.assertRaises(WardctlError):
            privilege.elevation_argv(["update"], launcher=os.path.abspath(__file__))

    def test_trusted_path_rejects_world_writable_parent(self):
        self.assertTrue(privilege.is_trusted_path("/usr/bin/python3"))
        self.assertFalse(privilege.is_trusted_path("/tmp"))


class FileSafetyTests(TempHomeCase):
    def test_private_dir_created_0700(self):
        d = os.path.join(self.home, ".wardctl")
        fsutil.ensure_private_dir(d, os.getuid())
        self.assertEqual(stat.S_IMODE(os.lstat(d).st_mode), 0o700)

    def test_symlinked_state_dir_refused(self):
        target = os.path.join(self.tmp, "elsewhere")
        os.mkdir(target)
        os.symlink(target, os.path.join(self.home, ".wardctl"))
        store = config.Store(make_identity(self.home))
        with self.assertRaises(UnsafePathError):
            store.ensure_dirs()
        with self.assertRaises(UnsafePathError):
            store.load_config()

    def test_group_writable_dir_refused(self):
        d = os.path.join(self.home, ".wardctl")
        os.mkdir(d)
        os.chmod(d, 0o770)
        with self.assertRaises(UnsafePathError):
            fsutil.ensure_private_dir(d, os.getuid())

    def test_wrong_owner_refused(self):
        d = os.path.join(self.home, ".wardctl")
        os.mkdir(d, 0o700)
        with self.assertRaises(UnsafePathError):
            fsutil.ensure_private_dir(d, os.getuid() + 1)

    def test_symlinked_config_file_not_followed(self):
        store = config.Store(make_identity(self.home))
        store.ensure_dirs()
        secret = os.path.join(self.tmp, "secret.json")
        with open(secret, "w") as fh:
            fh.write('{"schema_version": 1, "settings": {}, "apps": {}}')
        os.symlink(secret, store.paths.config)
        with self.assertRaises(UnsafePathError):
            store.load_config()

    def test_atomic_write_replaces_and_keeps_mode(self):
        path = os.path.join(self.home, "f.json")
        fsutil.atomic_write(path, b"one")
        fsutil.atomic_write(path, b"two")
        with open(path, "rb") as fh:
            self.assertEqual(fh.read(), b"two")
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertEqual([f for f in os.listdir(self.home) if f.endswith(".tmp")], [])

    def test_atomic_write_failure_leaves_original(self):
        path = os.path.join(self.home, "f.json")
        fsutil.atomic_write(path, b"original")
        with mock.patch("os.replace", side_effect=OSError("disk full")), self.assertRaises(OSError):
            fsutil.atomic_write(path, b"new")
        with open(path, "rb") as fh:
            self.assertEqual(fh.read(), b"original")
        self.assertEqual([f for f in os.listdir(self.home) if f.endswith(".tmp")], [])

    def test_atomic_write_refuses_symlink_target(self):
        os.symlink("/etc/passwd", os.path.join(self.home, "x"))
        with self.assertRaises(UnsafePathError):
            fsutil.atomic_write(os.path.join(self.home, "x"), b"data")


class ConfigTests(TempHomeCase):
    def store(self, **kw):
        return config.Store(make_identity(self.home), **kw)

    def test_roundtrip_and_permissions(self):
        s = self.store()
        cfg = config.new_config()
        s.save_config(cfg)
        loaded, migrated = s.load_config()
        self.assertEqual(loaded, cfg)
        self.assertFalse(migrated)
        self.assertEqual(stat.S_IMODE(os.stat(s.paths.config).st_mode), 0o600)

    def test_malformed_json_is_reported_and_not_overwritten(self):
        s = self.store()
        s.ensure_dirs()
        with open(s.paths.config, "w") as fh:
            fh.write('{"schema_version": 1, "apps": {,}}')
        os.chmod(s.paths.config, 0o600)
        with self.assertRaises(ConfigError) as cm:
            s.load_config()
        self.assertIn("line 1", str(cm.exception))
        with open(s.paths.config) as fh:
            self.assertIn("{,}", fh.read())

    def test_schema_errors_are_specific(self):
        cfg = config.new_config()
        cfg["apps"]["x"] = {"id": "x", "display_name": "X", "kind": "deb", "packages": ["xx"],
                            "source": {"resolver": "direct-deb", "url": "http://insecure.example/x.deb",
                                       "approved_hosts": ["insecure.example"]}}
        with self.assertRaises(ConfigError) as cm:
            config.validate(cfg)
        self.assertIn("https", str(cm.exception))
        cfg["apps"]["x"]["source"]["url"] = "https://ok.example/x.deb"
        cfg["apps"]["x"]["hook"] = "/bin/sh -c evil"
        with self.assertRaises(ConfigError) as cm:
            config.validate(cfg)
        self.assertIn("unknown keys: hook", str(cm.exception))

    def test_no_executable_fields_accepted(self):
        cfg = config.new_config()
        cfg["settings"]["apt_get_path"] = "/tmp/evil"
        with self.assertRaises(ConfigError):
            config.validate(cfg)

    def test_newer_schema_refused_untouched(self):
        s = self.store()
        s.ensure_dirs()
        body = json.dumps({"schema_version": 99, "apps": {}})
        with open(s.paths.config, "w") as fh:
            fh.write(body)
        os.chmod(s.paths.config, 0o600)
        with self.assertRaises(ConfigError):
            s.load_config()
        with open(s.paths.config) as fh:
            self.assertEqual(fh.read(), body)

    def test_migration_from_legacy_layout(self):
        legacy = {"apps": [{"id": "foo", "packages": ["foo"]}]}
        cfg, migrated = config.migrate(legacy)
        self.assertTrue(migrated)
        self.assertEqual(cfg["schema_version"], 1)
        self.assertEqual(cfg["apps"]["foo"]["display_name"], "foo")
        config.validate(cfg)

    def test_dry_run_store_refuses_writes(self):
        s = self.store(read_only=True)
        with self.assertRaises(RuntimeError):
            s.save_config(config.new_config())
        with self.assertRaises(RuntimeError):
            s.save_state({})
        self.assertFalse(os.path.exists(s.paths.root))

    def test_corrupt_state_is_preserved_and_reset(self):
        s = self.store()
        s.ensure_dirs()
        with open(s.paths.state, "w") as fh:
            fh.write("not json")
        os.chmod(s.paths.state, 0o600)
        state = s.load_state()
        self.assertTrue(state["corrupt_state_recovered"])
        self.assertTrue(os.path.exists(s.paths.state + ".corrupt"))

    def test_user_lock_contention(self):
        from wardctl.errors import LockBusy
        s = self.store()
        with s.user_lock():
            with self.assertRaises(LockBusy):
                with self.store().user_lock():
                    pass
        with s.user_lock():  # released properly
            pass


class ExampleConfigTests(unittest.TestCase):
    def test_shipped_example_validates(self):
        from helpers import ROOT
        with open(os.path.join(ROOT, "examples", "config.example.json")) as fh:
            config.validate(json.load(fh))

    def test_catalog_records_validate(self):
        from wardctl import catalog
        cfg = config.new_config()
        for app_id in catalog.CATALOG:
            cfg["apps"][app_id] = catalog.to_record(catalog.get(app_id))
        config.validate(cfg)


class AptLockProbeTests(TempHomeCase):
    def test_reports_holder_without_taking_or_removing_lock(self):
        import subprocess
        import sys
        import time
        from wardctl import locks
        path = os.path.join(self.tmp, "lock-frontend")
        open(path, "w").close()
        holder = subprocess.Popen([sys.executable, "-c",
                                   "import fcntl,sys,time; f=open(sys.argv[1],'w'); fcntl.lockf(f, fcntl.LOCK_EX); "
                                   "print('locked', flush=True); time.sleep(30)", path],
                                  stdout=subprocess.PIPE, text=True)
        self.addCleanup(holder.kill)
        self.assertEqual(holder.stdout.readline().strip(), "locked")
        self.assertEqual(locks.apt_lock_holder([path]), (path, holder.pid))
        self.assertTrue(os.path.exists(path))
        self.assertIsNone(holder.poll())  # holder untouched
        holder.kill()
        holder.wait()
        self.assertIsNone(locks.apt_lock_holder([path]))


if __name__ == "__main__":
    unittest.main()
