import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from account_repository import get_repository
from auth_utils import hash_password, verify_password
from config import AppConfig, quote_identifier
from Quan_Ly_SuperAdmin import change_superadmin_password
from rbac_repository import ensure_rbac_seeded, validate_seed


ROOT = Path(__file__).resolve().parents[1]


class PasswordTests(unittest.TestCase):
    def test_password_is_not_trimmed(self):
        stored = hash_password("  spaced secret  ", 10_000)
        self.assertTrue(verify_password("  spaced secret  ", stored))
        self.assertFalse(verify_password("spaced secret", stored))

    def test_malformed_and_extreme_hashes_fail_safely(self):
        for value in (None, "", "pbkdf2_sha256$0$$", "pbkdf2_sha256$999999999$x$y",
                      "pbkdf2_sha256$10000$zz$00", "pbkdf2_sha256$10000$" + "00" * 16 + "$00"):
            self.assertFalse(verify_password("password", value))
        self.assertFalse(verify_password("password", "x" * 10_000_000))


class ConfigTests(unittest.TestCase):
    def test_identifiers_are_validated(self):
        self.assertEqual(quote_identifier("safe_name"), '"safe_name"')
        for value in ("bad-name", 'x"; DROP TABLE users;--', "a.b", ""):
            with self.subTest(value=value), self.assertRaises(ValueError):
                quote_identifier(value)

    def test_config_rejects_reserved_and_duplicate_columns(self):
        for names in (("username",), ("display_name", "DISPLAY_NAME"), ("bad;drop",)):
            with self.subTest(names=names), self.assertRaises(ValueError):
                AppConfig(extra_field_names=names)

    def test_postgres_requires_credentials(self):
        with self.assertRaisesRegex(ValueError, "QMS_PGDATABASE"):
            AppConfig(db_backend="postgres")


class SQLiteRepositoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.cfg = AppConfig(
            base_dir=self.temp.name, db_filename="test.sqlite",
            pbkdf2_iterations=10_000, min_password_length=8,
        )

    def test_atomic_bootstrap_and_idempotent_seed(self):
        repo = get_repository(self.cfg)
        repo.initialize()
        self.assertFalse(repo.is_installed())
        rbac = ensure_rbac_seeded(self.cfg)
        rbac.seed_from_dict(json.loads(Path(self.cfg.rbac_seed_path).read_text(encoding="utf-8")))
        self.assertEqual(len(rbac.list_permissions()), 17)
        self.assertTrue(rbac.user_has_permission("not-created", "system.manage_users") is False)

        seed = json.loads(Path(self.cfg.rbac_seed_path).read_text(encoding="utf-8"))
        repo.bootstrap_account("admin", hash_password("strong password", 10_000), {}, seed)
        self.assertTrue(repo.is_installed())
        self.assertEqual(repo.get_by_username("admin").username, "admin")
        self.assertTrue(rbac.user_has_permission("admin", "system.manage_users"))
        self.assertEqual(len(rbac.list_roles()), 8)

        with self.assertRaisesRegex(ValueError, "đã được khởi tạo"):
            repo.bootstrap_account("another", hash_password("different password", 10_000), {}, seed)

    def test_invalid_seed_does_not_partially_write(self):
        repo = get_repository(self.cfg)
        repo.initialize()
        invalid = {
            "departments": [{"name": "D"}],
            "permissions": [{"code": "a", "name": "A", "module": "M"}],
            "roles": [{"name": "R", "permissions": ["unknown.permission"]}],
        }
        with self.assertRaises(ValueError):
            repo.bootstrap_account("admin", hash_password("strong password", 10_000), {}, invalid)
        self.assertFalse(repo.is_installed())
        conn = self.cfg.connect()
        try:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM users").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM departments").fetchone()[0], 0)
        finally:
            conn.close()

    def test_password_change_audits_without_passwords(self):
        repo = get_repository(self.cfg)
        repo.initialize()
        repo.create_account("admin", hash_password("old password", 10_000), {})
        ok, _ = change_superadmin_password(self.cfg, "admin", "old password", "new password")
        self.assertTrue(ok)
        self.assertTrue(verify_password("new password", repo.get_by_username("admin").password_hash))
        audit = Path(self.cfg.audit_log_path).read_text(encoding="utf-8")
        self.assertNotIn("old password", audit)
        self.assertNotIn("new password", audit)

    def test_concurrent_password_update_uses_compare_and_swap(self):
        repo = get_repository(self.cfg)
        repo.initialize()
        old_hash = hash_password("old password", 10_000)
        repo.create_account("admin", old_hash, {})
        self.assertTrue(repo.update_password_if_current(
            "admin", old_hash, hash_password("replacement", 10_000)
        ))
        self.assertFalse(repo.update_password_if_current(
            "admin", old_hash, hash_password("stale replacement", 10_000)
        ))

    def test_only_one_concurrent_bootstrap_wins(self):
        repo = get_repository(self.cfg)
        repo.initialize()
        seed = json.loads(Path(self.cfg.rbac_seed_path).read_text(encoding="utf-8"))
        start = threading.Barrier(2)
        outcomes = []

        def bootstrap(username):
            start.wait()
            try:
                repo.bootstrap_account(username, hash_password("strong password", 10_000), {}, seed)
                outcomes.append("success")
            except ValueError:
                outcomes.append("rejected")

        threads = [threading.Thread(target=bootstrap, args=(name,)) for name in ("admin1", "admin2")]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertCountEqual(outcomes, ["success", "rejected"])
        self.assertTrue(repo.is_installed())

    def test_audit_failure_after_update_is_not_hidden(self):
        repo = get_repository(self.cfg)
        repo.initialize()
        repo.create_account("admin", hash_password("old password", 10_000), {})
        with patch("Quan_Ly_SuperAdmin._write_audit", return_value=False):
            success, message = change_superadmin_password(self.cfg, "admin", "old password", "new password")
        self.assertTrue(success)
        self.assertIn("không ghi được audit log", message)


class SeedValidationTests(unittest.TestCase):
    def test_duplicate_and_unknown_permission_rejected(self):
        with self.assertRaises(ValueError):
            validate_seed({"departments": [{"name": "D"}, {"name": "D"}],
                           "permissions": [], "roles": []})
        with self.assertRaises(ValueError):
            validate_seed({"departments": [], "permissions": [],
                           "roles": [{"name": "R", "permissions": ["unknown"]}]})


if __name__ == "__main__":
    unittest.main()
