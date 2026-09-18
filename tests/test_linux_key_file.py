import hashlib
import hmac
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from wechat_ai_bot.services.core.linux_key_file import (
    KeyFileError, load_key_file, merge_key_file, read_document,
)


class KeyFileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = self.root / "account/db_storage/message/message_0.db"
        self.db.parent.mkdir(parents=True)
        self.relative = self.db.relative_to(self.root).as_posix()
        self.file = self.root / "keys.json"
        self.key = bytes(range(32))
        page = bytearray(os.urandom(4096))
        salt = bytes(x ^ 0x3a for x in page[:16])
        mac = hashlib.pbkdf2_hmac("sha512", self.key, salt, 2, dklen=32)
        page[-64:] = hmac.digest(mac, bytes(page[16:4032]) + struct.pack("<I", 1), "sha512")
        self.db.write_bytes(page)
        self.material = self.key.hex() + page[:16].hex()

    def write(self, data):
        self.file.write_text(json.dumps({"version": 1, "keys": data}))
        self.file.chmod(0o600)

    def load(self):
        return load_key_file(self.file, self.root, [self.db])

    def test_round_trip_and_redacted_status(self):
        merge_key_file(self.file, self.root, {self.relative: self.material})
        self.assertEqual(self.file.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.load().keys, {self.db: self.material})
        self.assertNotIn(self.material, str(self.load()))
        self.assertNotIn(self.material, str(self.load().redacted()))

    def test_wrong_key_and_changed_salt_rejected(self):
        self.write({self.relative: "ff" * 32 + self.material[64:]})
        self.assertEqual(self.load().invalid_count, 1)
        self.write({self.relative: self.material})
        page = bytearray(self.db.read_bytes())
        page[0] ^= 1
        self.db.write_bytes(page)
        self.assertFalse(self.load().keys)

    def test_missing_corrupt_and_permission_errors(self):
        self.assertIn("missing", self.load().error)
        self.file.write_text("{broken sensitive-marker")
        self.file.chmod(0o600)
        self.assertNotIn("sensitive-marker", self.load().error)
        self.assertTrue(self.load().error)
        self.write({self.relative: self.material})
        self.file.chmod(0o644)
        self.assertIn("0600", self.load().error)

    def test_outside_paths_symlinks_and_undiscovered_files(self):
        self.write({"../escape.db": self.material, str(self.db): self.material})
        self.assertEqual(self.load().invalid_count, 2)
        self.write({self.relative: self.material})
        self.assertEqual(load_key_file(self.file, self.root, []).invalid_count, 1)
        link = self.root / "linked.json"
        link.symlink_to(self.file)
        self.assertTrue(load_key_file(link, self.root, [self.db]).error)
        with self.assertRaises(KeyFileError):
            merge_key_file(link, self.root, {})

    def test_failed_replacement_preserves_previous_file(self):
        self.write({self.relative: self.material})
        previous = self.file.read_bytes()
        with patch("os.replace", side_effect=OSError("fixture failure")):
            with self.assertRaises(OSError):
                merge_key_file(self.file, self.root, {self.relative: self.material})
        self.assertEqual(self.file.read_bytes(), previous)
        self.assertEqual(list(self.root.glob(".database-keys-*")), [])
        with self.assertRaises(KeyFileError):
            merge_key_file(self.file, self.root, {self.relative: "00" * 48})
        self.assertEqual(self.file.read_bytes(), previous)


if __name__ == "__main__":
    unittest.main()
