"""End-to-end service tests using disposable, encrypted fixture databases."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


@unittest.skipUnless(importlib.util.find_spec("sqlcipher3"), "requires SQLCipher driver")
class FileKeyServiceTests(unittest.TestCase):
    def setUp(self):
        import sqlcipher3
        from wechat_ai_bot.models import UserInfo
        from wechat_ai_bot.services.core.linux_database_service import LinuxDatabaseService, MESSAGE_COLUMNS
        from wechat_ai_bot.services.core.linux_key_file import merge_key_file
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.key_file = self.root / "credentials.json"
        storage = self.root / "fixture_account/db_storage"
        self.message = storage / "message/message_0.db"
        self.contact = storage / "contact/contact.db"
        self.key = bytes(range(32)).hex() + bytes(range(16)).hex()
        self.connections = []

        def connect(path):
            path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlcipher3.connect(str(path))
            conn.execute(f'''PRAGMA key="x'{self.key}'"''')
            self.connections.append(conn)
            self.addCleanup(conn.close)
            return conn

        contacts = connect(self.contact)
        contacts.execute("CREATE TABLE contact (" + ",".join(f"c{i}" for i in range(22)) + ")")
        row = [0] * 22
        row[0], row[1], row[11] = 1, "fixture_peer", "Fixture"
        row[3], row[8], row[20] = "", "", b""
        contacts.execute("INSERT INTO contact VALUES (" + ",".join("?" * 22) + ")", row)
        contacts.execute("CREATE TABLE chat_room (unused)")
        contacts.commit()
        self.writer = connect(self.message)
        self.writer.execute("CREATE TABLE Name2Id (user_name TEXT)")
        self.writer.execute("INSERT INTO Name2Id VALUES ('fixture_peer')")
        self.table = "Msg_" + hashlib.md5(b"fixture_peer").hexdigest()
        self.writer.execute(f'CREATE TABLE "{self.table}" (' + ",".join(f'"{c}"' for c in MESSAGE_COLUMNS) + ")")
        self.add_message(1)
        merge_key_file(self.key_file, self.root, {
            p.relative_to(self.root).as_posix(): self.key for p in (self.message, self.contact)
        })
        self.factory = lambda: LinuxDatabaseService(UserInfo(account="fixture"),
            xwechat_files_root=self.root, key_file=self.key_file, scan_keys=True, key_retry_interval=0)
        self.scan = patch("wechat_ai_bot.services.core.linux_database_service.SqlCipherKeyScanner.scan",
                          side_effect=AssertionError("scanner must not run with key_file"))
        self.scan.start()
        self.addCleanup(self.scan.stop)

    def add_message(self, local_id):
        values = [local_id, 1000 + local_id, 1, 100 + local_id, 1, 100 + local_id,
                  0, 0, 0, 0, 0, "", "fixture", b"", b"", 0, 0]
        self.writer.execute(f'INSERT INTO "{self.table}" VALUES (' + ",".join("?" * 17) + ")", values)
        self.writer.commit()

    def test_file_to_query_poll_refresh_and_restart(self):
        service = self.factory()
        self.addCleanup(service.stop)
        service.setup()
        self.assertTrue(service.get_status()["core_ready"], service.get_status())
        self.assertEqual(len(service.get_messages_by_username("fixture_peer", count=10)), 1)
        self.assertEqual(service.check_new_messages(), [])
        self.add_message(2)
        service.refresh()
        self.assertEqual(len(service.check_new_messages()), 1)
        self.assertEqual(service.check_new_messages(), [])
        service.stop()
        restarted = self.factory()
        self.addCleanup(restarted.stop)
        restarted.setup()
        self.assertTrue(restarted.get_status()["core_ready"])
        self.assertEqual(len(restarted.get_messages_by_username("fixture_peer", count=10)), 2)
        self.assertEqual(restarted.check_new_messages(), [])

    def test_invalidated_file_clears_state_and_recovers_after_repair(self):
        service = self.factory()
        self.addCleanup(service.stop)
        service.setup()
        self.key_file.chmod(0o644)
        service.refresh()
        self.assertFalse(service.is_available)
        self.assertFalse(service._keys)
        self.assertFalse(service._connections)
        self.assertFalse(service._contact_by_username)
        self.key_file.chmod(0o600)
        service.check_new_messages()
        self.assertTrue(service.get_status()["core_ready"])

    def test_all_numbered_shards_require_keys_and_readable_schema(self):
        import sqlcipher3
        from wechat_ai_bot.services.core.linux_key_file import merge_key_file
        second = self.message.with_name("message_1.db")
        connection = sqlcipher3.connect(str(second))
        connection.execute(f'''PRAGMA key="x'{self.key}'"''')
        connection.execute("CREATE TABLE unexpected_schema (value)")
        connection.commit()
        connection.close()
        service = self.factory()
        self.addCleanup(service.stop)
        service.setup()
        self.assertTrue(service.is_available)
        self.assertFalse(service.get_status()["core_ready"])
        self.assertIn("message/message_1.db", service.get_status()["core_missing_databases"])
        merge_key_file(self.key_file, self.root, {second.relative_to(self.root).as_posix(): self.key})
        service.refresh()
        self.assertFalse(service.get_status()["core_ready"])
        self.assertIn("message/message_1.db", service.get_status()["core_query_errors"])


if __name__ == "__main__":
    unittest.main()
