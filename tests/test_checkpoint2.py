import base64
import copy
import errno
import io
import json
import os
import pty
import select
import signal
import stat
import sys
import tempfile
import time
import unittest
import warnings
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

from password_manager import auth, cli, crypto
from password_manager.storage import locked_storage
from password_manager.validation import MAX_FILE, VaultError, json_bytes, load_json, validate_payload, wipe

MASTER = "Example master passphrase for tests only"
WRONG = "Incorrect master passphrase for tests only"
SECRET = "Dummy-entry-password-734!"
ENTRY = {
    "id": "a" * 32, "label": "Example account", "username": "demo-user",
    "password": SECRET, "notes": "Dummy note",
}


class CryptoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.master = bytearray(MASTER.encode())
        cls.salt = bytes(range(16))
        cls.key = crypto.derive_key(cls.master, cls.salt)
        cls.payload = {"entries": [ENTRY.copy()]}
        cls.raw = crypto.encrypt_vault(cls.payload, cls.key, cls.salt)

    @classmethod
    def tearDownClass(cls):
        wipe(cls.master)
        wipe(cls.key)

    def test_round_trip_and_no_cleartext_at_rest(self):
        payload, key, salt = crypto.decrypt_vault(self.raw, self.master)
        try:
            self.assertEqual(payload, self.payload)
            self.assertEqual(salt, self.salt)
            self.assertEqual(len(key), 32)
            for value in (MASTER, SECRET, ENTRY["label"], ENTRY["username"], ENTRY["notes"]):
                self.assertNotIn(value.encode(), self.raw)
        finally:
            wipe(key)

    def test_wrong_password_and_tampering_fail(self):
        outer = json.loads(self.raw)
        damaged = copy.deepcopy(outer)
        ciphertext = bytearray(base64.b64decode(damaged["ciphertext"]))
        ciphertext[-1] ^= 1
        damaged["ciphertext"] = crypto.encode64(ciphertext)
        changed_salt = copy.deepcopy(outer)
        changed_salt["salt"] = crypto.encode64(b"s" * 16)
        changed_nonce = copy.deepcopy(outer)
        changed_nonce["nonce"] = crypto.encode64(b"n" * 12)
        cases = [
            (self.raw, bytearray(WRONG.encode())),
            (json_bytes(damaged), self.master),
            (json_bytes(changed_salt), self.master),
            (json_bytes(changed_nonce), self.master),
        ]
        for raw, master in cases:
            with self.subTest():
                with self.assertRaisesRegex(VaultError, "Cannot unlock vault"):
                    crypto.decrypt_vault(raw, master)

    def test_new_nonce_for_each_save(self):
        second = crypto.encrypt_vault(self.payload, self.key, self.salt)
        self.assertNotEqual(json.loads(self.raw)["nonce"], json.loads(second)["nonce"])
        self.assertEqual(json.loads(self.raw)["salt"], json.loads(second)["salt"])

    def test_bad_headers_rejected_before_key_derivation(self):
        outer = json.loads(self.raw)
        cases = []
        for field, value in (("version", True), ("salt", "invalid!"), ("extra", 1)):
            bad = copy.deepcopy(outer)
            bad[field] = value
            cases.append(json_bytes(bad))
        for field, value in (("memory_kib", 2**40), ("passes", 3.0), ("parallelism", True)):
            bad = copy.deepcopy(outer)
            bad["kdf"][field] = value
            cases.append(json_bytes(bad))
        cases.append(b'{"version":1,"version":1}')
        cases.append(b"x" * (MAX_FILE + 1))
        with patch("password_manager.crypto.derive_key") as derive:
            for raw in cases:
                with self.subTest():
                    with self.assertRaises(VaultError):
                        crypto.decrypt_vault(raw, self.master)
            derive.assert_not_called()

    def test_payload_limits_and_controls(self):
        for field, value in (("label", "\x1b[31m"), ("username", "x" * 257), ("notes", "x" * 4097)):
            payload = copy.deepcopy(self.payload)
            payload["entries"][0][field] = value
            with self.subTest(field=field):
                with self.assertRaises(VaultError):
                    validate_payload(payload)
        with self.assertRaises(VaultError):
            validate_payload({"entries": [ENTRY.copy()] * 501})
        with self.assertRaises(VaultError):
            validate_payload({"entries": [ENTRY.copy(), ENTRY.copy()]})
        with self.assertRaises(VaultError):
            load_json(b'{"entries": NaN}')


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix=".test-vault-", dir=Path.home())
        self.home = Path(self.temporary.name)
        self.directory = self.home / ".securepm"
        self.vault = self.directory / "vault.json"

    def tearDown(self):
        self.temporary.cleanup()

    def create(self):
        with locked_storage(create=True, home=self.home) as storage:
            storage.create(b"encrypted fixture")

    def test_modes_exclusive_create_and_replace(self):
        self.create()
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.vault.stat().st_mode), 0o600)
        lock = self.directory / "vault.lock"
        self.assertEqual(stat.S_IMODE(lock.stat().st_mode), 0o600)
        original_lock = lock.stat().st_ino
        with locked_storage(home=self.home) as storage:
            with self.assertRaises(VaultError):
                storage.create(b"replacement")
            self.assertEqual(storage.read(), b"encrypted fixture")
            storage.save(b"new encrypted fixture")
            self.assertEqual(storage.read(), b"new encrypted fixture")
        self.assertEqual(lock.stat().st_ino, original_lock)

    def test_second_command_cannot_lock(self):
        with locked_storage(create=True, home=self.home):
            with self.assertRaisesRegex(VaultError, "busy"):
                with locked_storage(home=self.home):
                    self.fail("Concurrent lock was granted")

    def test_symlinks_and_hardlinks_are_rejected(self):
        self.create()
        target = self.home / "target"
        self.vault.rename(target)
        self.vault.symlink_to(target)
        with locked_storage(home=self.home) as storage:
            with self.assertRaises(OSError):
                storage.read()
        self.assertEqual(target.read_bytes(), b"encrypted fixture")
        self.vault.unlink()
        os.link(target, self.vault)
        with locked_storage(home=self.home) as storage:
            with self.assertRaises(VaultError):
                storage.read()

    def test_unsafe_permissions_and_oversize_are_rejected(self):
        self.create()
        self.vault.chmod(0o644)
        with locked_storage(home=self.home) as storage:
            with self.assertRaises(VaultError):
                storage.read()
        self.vault.chmod(0o600)
        with self.vault.open("wb") as stream:
            stream.truncate(MAX_FILE + 1)
        with locked_storage(home=self.home) as storage:
            with self.assertRaises(VaultError):
                storage.read()
        self.directory.chmod(0o755)
        with self.assertRaises(VaultError):
            with locked_storage(home=self.home):
                self.fail("Unsafe directory accepted")

    def test_failed_write_preserves_old_vault(self):
        self.create()
        before = self.vault.read_bytes()
        with locked_storage(home=self.home) as storage:
            with patch("password_manager.storage.os.fsync", side_effect=OSError("simulated")):
                with self.assertRaises(OSError):
                    storage.save(b"changed encrypted fixture")
        self.assertEqual(self.vault.read_bytes(), before)
        self.assertEqual(list(self.directory.glob("*.tmp")), [])


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix=".test-vault-", dir=Path.home())
        self.home = Path(self.temporary.name)
        self.vault = self.home / ".securepm" / "vault.json"

    def tearDown(self):
        self.temporary.cleanup()

    def run_cli(self, args, dialogue=()):
        sys.stdout.flush()
        sys.stderr.flush()
        pid, fd = pty.fork()
        if pid == 0:
            try:
                with patch("password_manager.storage.Path.home", return_value=self.home):
                    code = cli.main(args)
                sys.stdout.flush()
                sys.stderr.flush()
                os._exit(code)
            except BaseException:
                os._exit(99)
        output = b""
        cursor = 0
        step = 0
        deadline = time.monotonic() + 15
        status = None
        try:
            while time.monotonic() < deadline:
                if select.select([fd], [], [], 0.1)[0]:
                    try:
                        chunk = os.read(fd, 65536)
                    except OSError as error:
                        if error.errno != errno.EIO:
                            raise
                        break
                    if not chunk:
                        break
                    output += chunk
                    if step < len(dialogue):
                        prompt, response = dialogue[step]
                        position = output.find(prompt.encode(), cursor)
                        if position != -1:
                            cursor = position + len(prompt)
                            os.write(fd, (response + "\n").encode())
                            step += 1
                done, child_status = os.waitpid(pid, os.WNOHANG)
                if done:
                    status = child_status
                    # Read any last buffered terminal output before leaving.
                    while select.select([fd], [], [], 0)[0]:
                        try:
                            chunk = os.read(fd, 65536)
                        except OSError:
                            break
                        if not chunk:
                            break
                        output += chunk
                    break
            else:
                os.kill(pid, signal.SIGKILL)
                self.fail("CLI timed out")
        finally:
            os.close(fd)
            if status is None:
                _, status = os.waitpid(pid, 0)
        return os.waitstatus_to_exitcode(status), output.decode("utf-8", errors="replace")

    def initialize(self):
        code, output = self.run_cli(["init"], [
            ("New master password: ", MASTER), ("Confirm master password: ", MASTER),
        ])
        self.assertEqual(code, 0, output)
        self.assertNotIn(MASTER, output)

    def test_init_add_list_show_and_persistence(self):
        self.initialize()
        code, output = self.run_cli(["add"], [
            ("Master password: ", MASTER), ("Label: ", ENTRY["label"]),
            ("Username: ", ENTRY["username"]), ("Entry password: ", SECRET),
            ("Notes: ", ENTRY["notes"]),
        ])
        self.assertEqual(code, 0, output)
        self.assertNotIn(MASTER, output)
        self.assertNotIn(SECRET, output)
        payload, key, _ = crypto.decrypt_vault(self.vault.read_bytes(), bytearray(MASTER.encode()))
        try:
            self.assertEqual(payload["entries"][0]["password"], SECRET)
            identifier = payload["entries"][0]["id"]
        finally:
            wipe(key)
        for command in (["list"], ["show", identifier]):
            code, output = self.run_cli(command, [("Master password: ", MASTER)])
            self.assertEqual(code, 0, output)
            self.assertIn(ENTRY["label"], output)
            self.assertNotIn(SECRET, output)
            self.assertNotIn(MASTER, output)
            if command[0] == "show":
                self.assertIn("Password: [hidden]", output)

    def test_failed_unlock_and_repeated_init_do_not_write(self):
        self.initialize()
        before = self.vault.read_bytes()
        code, output = self.run_cli(["add"], [("Master password: ", WRONG)])
        self.assertEqual(code, 1)
        self.assertIn("Cannot unlock vault", output)
        self.assertNotIn("Label:", output)
        self.assertNotIn(WRONG, output)
        self.assertEqual(self.vault.read_bytes(), before)
        code, output = self.run_cli(["init"])
        self.assertEqual(code, 1)
        self.assertIn("already exists", output)
        self.assertEqual(self.vault.read_bytes(), before)

    def test_short_master_and_mismatch_do_not_create_vault(self):
        code, _ = self.run_cli(["init"], [("New master password: ", "too short")])
        self.assertEqual(code, 1)
        self.assertFalse(self.vault.exists())
        code, _ = self.run_cli(["init"], [
            ("New master password: ", MASTER), ("Confirm master password: ", WRONG),
        ])
        self.assertEqual(code, 1)
        self.assertFalse(self.vault.exists())

    def test_bad_id_and_arguments_do_not_echo_secrets(self):
        code, output = self.run_cli(["show", "../vault.json"])
        self.assertEqual(code, 1)
        self.assertIn("32 lowercase hexadecimal", output)
        self.assertNotIn("Master password:", output)
        output = io.StringIO()
        with redirect_stderr(output), self.assertRaises(SystemExit):
            cli.parser().parse_args(["add", "--password", SECRET])
        self.assertNotIn(SECRET, output.getvalue())

    def test_hidden_input_fails_closed_and_redirects_rejected(self):
        def warning(*args, **kwargs):
            warnings.warn("hidden input unavailable", auth.getpass.GetPassWarning)
        with patch.object(auth, "require_terminal"), patch.object(auth.getpass, "getpass", warning):
            with self.assertRaises(VaultError):
                auth.secret_text("Password: ")
        with patch.object(sys.stdin, "isatty", return_value=False):
            with self.assertRaises(VaultError):
                auth.require_terminal()


if __name__ == "__main__":
    unittest.main()
