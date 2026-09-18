"""Verify a disposable SQLCipher copy, or run entirely synthetic self-tests.

Input is JSON on stdin. Neither credentials nor database rows are printed.
This module does not inspect processes, obtain keys, or change cipher defaults.
"""
from __future__ import annotations

import io
import json
from pathlib import Path
import sys
import tempfile


def verify(stream, path="/probe/data.db"):
    connection = None
    stage = "input"
    try:
        value = json.load(stream)
        key = value["key"]
        if not isinstance(key, str) or len(key) != 96 or len(bytes.fromhex(key)) != 48:
            raise ValueError("expected raw key and salt")
        # Only the explicitly provided disposable copy may be opened. Avoid
        # silently creating an empty DB when a mount or path is incorrect.
        stage = "copy_path"
        if not Path(path).is_file():
            raise FileNotFoundError
        stage = "driver"
        import sqlcipher3
        stage = "open"
        connection = sqlcipher3.connect(str(path))
        connection.execute(f'''PRAGMA key = "x'{key}'"''')
        connection.execute("PRAGMA query_only=ON")
        stage = "schema"
        count = connection.execute("SELECT count(*) FROM sqlite_master").fetchone()[0]
        stage = "quick_check"
        result = connection.execute("PRAGMA quick_check").fetchall()
        return {"opened": True, "schema_entries": count,
                "quick_check_ok": result == [("ok",)]}
    except Exception as exc:
        # SQLite/driver exception text can include input values or paths.
        return {"opened": False, "quick_check_ok": False,
                "stage": stage, "error_type": type(exc).__name__}
    finally:
        if connection is not None:
            connection.close()


def self_test():
    import sqlcipher3

    # Public, deterministic fixture material: no real account or database data.
    key = bytes(range(32)).hex() + bytes(range(16)).hex()
    wrong = (b"\xff" * 32).hex() + bytes(range(16)).hex()
    with tempfile.TemporaryDirectory(prefix="sqlcipher-fixture-") as directory:
        path = Path(directory) / "fixture.db"
        connection = sqlcipher3.connect(str(path))
        connection.execute(f'''PRAGMA key = "x'{key}'"''')
        connection.execute("CREATE TABLE fixture (value INTEGER)")
        connection.execute("INSERT INTO fixture VALUES (42)")
        connection.commit()
        connection.close()
        before = path.read_bytes()
        valid = verify(io.StringIO(json.dumps({"key": key})), path)
        invalid = verify(io.StringIO(json.dumps({"key": wrong})), path)
        missing = verify(io.StringIO(""), path)
        malformed = verify(io.StringIO('{"key":"invalid"}'), path)
        result = {
            "synthetic_only": True,
            "correct_key_opens_and_checks": valid.get("quick_check_ok", False),
            "wrong_key_rejected": not invalid["opened"] and invalid.get("stage") == "schema",
            "missing_stdin_identified": missing.get("stage") == "input",
            "malformed_input_identified": malformed.get("stage") == "input",
            "database_unchanged": path.read_bytes() == before,
        }
        result["success"] = all(result.values())
        return result


if __name__ == "__main__":
    result = self_test() if sys.argv[1:] == ["--self-test"] else verify(sys.stdin)
    print(json.dumps(result))
    raise SystemExit(0 if result.get("success", result.get("quick_check_ok", False)) else 2)
