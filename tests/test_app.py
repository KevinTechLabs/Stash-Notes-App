"""Tests for Stash: key derivation, encryption at rest, login/lockout, CSRF and
the add/edit/delete flow. Each test gets its own throwaway database and config.

    python3 -m unittest discover -s tests -v     (or: pytest)
"""

import importlib
import os
import pathlib
import sqlite3
import sys
import tempfile
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

stash = importlib.import_module("app")

PASSWORD = "correct horse battery"


class StashTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self._saved = (stash.DATABASE, stash.CONFIG_FILE)
        stash.DATABASE = os.path.join(d, "stash.db")
        stash.CONFIG_FILE = os.path.join(d, "stash_config.json")
        stash.FAILED_LOGIN_ATTEMPTS = 0
        stash.LOGIN_LOCKOUT_UNTIL = 0
        stash.SESSION_FERNETS.clear()
        stash.SESSION_ACTIVITY.clear()
        stash.init_db()
        stash.app.config["TESTING"] = True
        # Session cookies are Secure-only, so talk to the app over https.
        self.client = stash.app.test_client()
        self.client.environ_base["wsgi.url_scheme"] = "https"

    def tearDown(self):
        stash.DATABASE, stash.CONFIG_FILE = self._saved
        self.tmp.cleanup()

    def post(self, path, **form):
        form.setdefault("csrf_token", stash.CSRF_TOKEN)
        return self.client.post(path, data=form)

    def set_up_vault(self):
        r = self.post("/login", password=PASSWORD, confirm=PASSWORD)
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r.headers["Location"], "/")

    def rows(self):
        db = sqlite3.connect(stash.DATABASE)
        try:
            return db.execute("SELECT id, name, username, password, category, notes FROM entries").fetchall()
        finally:
            db.close()


class CryptoTest(StashTestCase):
    def test_derive_key_is_deterministic_and_salted(self):
        k1, v1 = stash.derive_key(PASSWORD, b"\x00" * 16)
        k2, v2 = stash.derive_key(PASSWORD, b"\x00" * 16)
        k3, _ = stash.derive_key(PASSWORD, b"\x01" * 16)
        self.assertEqual((k1, v1), (k2, v2))
        self.assertNotEqual(k1, k3)
        self.assertEqual(len(v1), 32)

    def test_key_and_verifier_are_independent_halves(self):
        key, verifier = stash.derive_key(PASSWORD, b"\x02" * 16)
        self.assertNotIn(verifier, key)

    def test_unlock_requires_the_right_password(self):
        stash.create_config(PASSWORD)
        self.assertIsNotNone(stash.unlock(PASSWORD))
        self.assertIsNone(stash.unlock(PASSWORD + "!"))

    def test_unlock_without_config(self):
        self.assertIsNone(stash.unlock(PASSWORD))

    def test_config_file_is_private_and_has_no_key(self):
        stash.create_config(PASSWORD)
        self.assertEqual(os.stat(stash.CONFIG_FILE).st_mode & 0o777, 0o600)
        text = pathlib.Path(stash.CONFIG_FILE).read_text()
        self.assertNotIn(PASSWORD, text)
        self.assertEqual(sorted(__import__("json").loads(text)), ["salt", "verifier"])

    def test_encrypt_round_trip(self):
        stash.create_config(PASSWORD)
        f = stash.unlock(PASSWORD)
        token = stash.encrypt(f, "s3cret ✓")
        self.assertNotIn("s3cret", token)
        self.assertEqual(stash.decrypt(f, token), "s3cret ✓")
        self.assertEqual(stash.decrypt(f, stash.encrypt(f, None)), "")
        self.assertEqual(stash.decrypt(f, ""), "")


class LoginTest(StashTestCase):
    def test_home_redirects_to_login_when_locked(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r.headers["Location"], "/login")

    def test_setup_rejects_short_password(self):
        r = self.post("/login", password="short", confirm="short")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"at least 12 characters", r.data)
        self.assertFalse(os.path.exists(stash.CONFIG_FILE))

    def test_setup_rejects_mismatched_confirmation(self):
        r = self.post("/login", password=PASSWORD, confirm=PASSWORD + "x")
        self.assertIn(b"do not match", r.data)
        self.assertFalse(os.path.exists(stash.CONFIG_FILE))

    def test_setup_then_logout_then_login(self):
        self.set_up_vault()
        self.assertEqual(self.client.get("/").status_code, 200)
        self.client.get("/logout")
        self.assertEqual(self.client.get("/").status_code, 302)
        r = self.post("/login", password=PASSWORD)
        self.assertEqual(r.headers["Location"], "/")
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_lockout_after_repeated_failures(self):
        stash.create_config(PASSWORD)
        for _ in range(stash.MAX_FAILED_LOGIN_ATTEMPTS - 1):
            r = self.post("/login", password="wrong password!")
            self.assertIn(b"Incorrect master password", r.data)
        r = self.post("/login", password="wrong password!")
        self.assertIn(b"Too many failed attempts", r.data)
        # Even the right password is refused during the lockout...
        r = self.post("/login", password=PASSWORD)
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"Too many failed attempts", r.data)
        # ...and accepted once it has expired.
        stash.LOGIN_LOCKOUT_UNTIL = time.time() - 1
        r = self.post("/login", password=PASSWORD)
        self.assertEqual(r.status_code, 302)

    def test_idle_session_is_locked(self):
        self.set_up_vault()
        sid = next(iter(stash.SESSION_ACTIVITY))
        stash.SESSION_ACTIVITY[sid] = time.time() - stash.AUTO_LOCK_SECONDS - 1
        r = self.client.get("/")
        self.assertEqual(r.headers["Location"], "/login")
        self.assertNotIn(sid, stash.SESSION_FERNETS)  # key dropped from memory

    def test_security_headers(self):
        r = self.client.get("/login")
        self.assertEqual(r.headers["X-Frame-Options"], "DENY")
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("frame-ancestors 'none'", r.headers["Content-Security-Policy"])


class EntriesTest(StashTestCase):
    def setUp(self):
        super().setUp()
        self.set_up_vault()

    def add(self, **fields):
        entry = {
            "name": "Router",
            "username": "admin",
            "password": "hunter2!",
            "category": "Network",
            "notes": "spare key in drawer",
        }
        entry.update(fields)
        return self.post("/add", **entry)

    def test_add_stores_only_ciphertext(self):
        self.add()
        (row,) = self.rows()
        for plain, stored in zip(
            ("Router", "admin", "hunter2!", "Network", "spare key in drawer"), row[1:], strict=True
        ):
            self.assertNotEqual(stored, plain)
            self.assertNotIn(plain, stored)

    def test_added_entry_is_shown_decrypted(self):
        self.add()
        r = self.client.get("/")
        self.assertIn(b"Router", r.data)
        self.assertIn(b"hunter2!", r.data)

    def test_entry_names_are_html_escaped(self):
        self.add(name="<script>alert(1)</script>")
        r = self.client.get("/")
        self.assertNotIn(b"<script>alert(1)</script>", r.data)
        self.assertIn(b"&lt;script&gt;", r.data)

    def test_add_without_name_is_ignored(self):
        self.add(name="   ")
        self.assertEqual(self.rows(), [])

    def test_add_requires_csrf_token(self):
        r = self.post("/add", name="x", csrf_token="forged")
        self.assertEqual(r.status_code, 403)
        self.assertEqual(self.rows(), [])

    def test_edit(self):
        self.add()
        ((entry_id, *_),) = self.rows()
        r = self.post(f"/edit/{entry_id}", name="Switch", username="root", password="p", category="Lab", notes="")
        self.assertEqual(r.status_code, 302)
        f = stash.unlock(PASSWORD)
        (row,) = self.rows()
        self.assertEqual(stash.decrypt(f, row[1]), "Switch")
        self.assertEqual(stash.decrypt(f, row[2]), "root")

    def test_edit_requires_csrf_and_name(self):
        self.add()
        ((entry_id, *_),) = self.rows()
        self.assertEqual(self.post(f"/edit/{entry_id}", name="x", csrf_token="bad").status_code, 403)
        self.assertEqual(self.post(f"/edit/{entry_id}", name="").status_code, 400)

    def test_delete(self):
        self.add()
        ((entry_id, *_),) = self.rows()
        self.assertEqual(self.post(f"/delete/{entry_id}", csrf_token="bad").status_code, 403)
        self.assertEqual(len(self.rows()), 1)
        self.post(f"/delete/{entry_id}")
        self.assertEqual(self.rows(), [])

    def test_rows_from_another_key_are_skipped(self):
        self.add(name="Mine")
        other = stash.Fernet(stash.Fernet.generate_key())
        db = sqlite3.connect(stash.DATABASE)
        db.execute(
            "INSERT INTO entries (name, username, password, category, notes) VALUES (?, ?, ?, ?, ?)",
            tuple(stash.encrypt(other, v) for v in ("Theirs", "u", "p", "c", "n")),
        )
        db.commit()
        db.close()
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"Mine", r.data)
        self.assertNotIn(b"Theirs", r.data)

    def test_entries_need_an_unlocked_session(self):
        self.client.get("/logout")
        self.add()
        self.assertEqual(self.rows(), [])


if __name__ == "__main__":
    unittest.main()
