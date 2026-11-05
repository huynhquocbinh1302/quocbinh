"""Kho tài khoản giao dịch cho SQLite và PostgreSQL."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from config import quote_identifier
from rbac_repository import _bootstrap_lock, initialize_rbac_schema, seed_on_connection, validate_seed

TABLE_NAME = "users"
LEGACY_TABLE_NAME = "super_admin"


@dataclass
class AdminAccount:
    username: str
    password_hash: str
    created_at: str
    failed_attempts: int = 0
    locked_until: Optional[str] = None
    extra: dict = field(default_factory=dict)


class AccountRepository:
    def __init__(self, cfg: Any):
        self.cfg = cfg

    def _transaction(self, write: bool = False):
        class Transaction:
            def __enter__(inner):
                inner.conn = self.cfg.connect()
                if write and self.cfg.db_backend == "sqlite":
                    inner.conn.execute("BEGIN IMMEDIATE")
                return inner.conn

            def __exit__(inner, exc_type, exc, tb):
                try:
                    inner.conn.rollback() if exc_type else inner.conn.commit()
                finally:
                    inner.conn.close()
                return False
        return Transaction()

    @staticmethod
    def _q(name: str) -> str:
        return quote_identifier(name)

    def _create_schema(self, conn: Any) -> None:
        config_table = self.cfg.table("system_config")
        users = self.cfg.table(TABLE_NAME)
        conn.execute(f"CREATE TABLE IF NOT EXISTS {config_table} (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        if self.cfg.db_backend == "sqlite":
            existing = {
                row[0] for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name IN (?,?)",
                    (TABLE_NAME, LEGACY_TABLE_NAME),
                ).fetchall()
            }
            if TABLE_NAME not in existing and LEGACY_TABLE_NAME in existing:
                conn.execute(f'ALTER TABLE "{LEGACY_TABLE_NAME}" RENAME TO "{TABLE_NAME}"')
            extra_defs = "".join(f", {self._q(name)} TEXT" for name in self.cfg.extra_field_names)
            conn.execute(
                f"""CREATE TABLE IF NOT EXISTS {users} (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL, is_first_login INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL, failed_attempts INTEGER NOT NULL DEFAULT 0,
                    locked_until TEXT{extra_defs})"""
            )
            columns = {row[1] for row in conn.execute(f"PRAGMA table_info({users})").fetchall()}
            for name, definition in (
                ("is_first_login", "INTEGER NOT NULL DEFAULT 0"),
                ("failed_attempts", "INTEGER NOT NULL DEFAULT 0"),
                ("locked_until", "TEXT"),
            ):
                if name not in columns:
                    conn.execute(f"ALTER TABLE {users} ADD COLUMN {self._q(name)} {definition}")
            for name in self.cfg.extra_field_names:
                if name not in columns:
                    conn.execute(f"ALTER TABLE {users} ADD COLUMN {self._q(name)} TEXT")
        else:
            extra_defs = "".join(f", {self._q(name)} TEXT" for name in self.cfg.extra_field_names)
            conn.execute(
                f"""CREATE TABLE IF NOT EXISTS {users} (
                    id BIGSERIAL PRIMARY KEY, username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL, is_first_login BOOLEAN NOT NULL DEFAULT FALSE,
                    created_at TEXT NOT NULL, failed_attempts INTEGER NOT NULL DEFAULT 0
                    CHECK(failed_attempts >= 0), locked_until TEXT{extra_defs})"""
            )
            for name in self.cfg.extra_field_names:
                conn.execute(f"ALTER TABLE {users} ADD COLUMN IF NOT EXISTS {self._q(name)} TEXT")
        initialize_rbac_schema(conn, self.cfg)

    def initialize(self) -> None:
        with self._transaction(write=True) as conn:
            if self._config_table_exists(conn) and self._is_installed(conn):
                return
            self._create_schema(conn)

    def _config_table_exists(self, conn: Any) -> bool:
        if self.cfg.db_backend == "sqlite":
            row = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                ("system_config",),
            ).fetchone()
            return row is not None
        row = conn.execute(
            "SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_schema=%s AND table_name=%s)",
            (self.cfg.postgres_schema, "system_config"),
        ).fetchone()
        return bool(row and row[0])

    def _is_installed(self, conn: Any) -> bool:
        row = conn.execute(
            f"SELECT value FROM {self.cfg.table('system_config')} WHERE key={self.cfg.placeholder}",
            ("is_installed",),
        ).fetchone()
        return bool(row and row[0] == "TRUE")

    def is_installed(self) -> bool:
        with self._transaction() as conn:
            if not self._config_table_exists(conn):
                return False
            return self._is_installed(conn)

    def mark_installed(self) -> None:
        p = self.cfg.placeholder
        with self._transaction(write=True) as conn:
            self._create_schema(conn)
            conn.execute(
                f"INSERT INTO {self.cfg.table('system_config')}(key,value) VALUES ({p},{p}) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                ("is_installed", "TRUE"),
            )

    def bootstrap_account(self, username: str, password_hash: str, extra: dict, seed: dict) -> None:
        seed = validate_seed(seed)
        if not any(item["name"] == "Admin" for item in seed["roles"]):
            raise ValueError("Seed RBAC phải khai báo role Admin.")
        if not any(item["name"] == "Ban Giám đốc" for item in seed["departments"]):
            raise ValueError("Seed RBAC phải khai báo bộ phận Ban Giám đốc.")
        p = self.cfg.placeholder
        with self._transaction(write=True) as conn:
            self._create_schema(conn)
            _bootstrap_lock(conn, self.cfg, "account-bootstrap")
            if self._is_installed(conn):
                raise ValueError("Hệ thống đã được khởi tạo.")
            now = datetime.now(timezone.utc).isoformat()
            columns = ["username", "password_hash", "is_first_login", "created_at", *self.cfg.extra_field_names]
            values = [username, password_hash, False, now]
            values.extend(extra.get(name, "") for name in self.cfg.extra_field_names)
            try:
                conn.execute(
                    f"INSERT INTO {self.cfg.table(TABLE_NAME)} "
                    f"({', '.join(self._q(name) for name in columns)}) "
                    f"VALUES ({', '.join([p] * len(values))})",
                    values,
                )
            except Exception as exc:
                if self.cfg.db_backend == "sqlite" and "UNIQUE constraint failed" in str(exc):
                    raise ValueError("Tên đăng nhập đã tồn tại.") from exc
                if getattr(exc, "sqlstate", None) == "23505":
                    raise ValueError("Tên đăng nhập đã tồn tại.") from exc
                raise
            seed_on_connection(conn, self.cfg, seed)
            conn.execute(
                f"""INSERT INTO {self.cfg.table('user_assignments')}
                    (username,role_name,department_name,assigned_at,assigned_by,is_active)
                    VALUES ({p},{p},{p},{p},{p},TRUE)""",
                (username, "Admin", "Ban Giám đốc", now, "bootstrap"),
            )
            conn.execute(
                f"INSERT INTO {self.cfg.table('system_config')}(key,value) VALUES ({p},{p}) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                ("is_installed", "TRUE"),
            )

    def get_by_username(self, username: str) -> Optional[AdminAccount]:
        base = ["username", "password_hash", "created_at", "failed_attempts", "locked_until"]
        columns = base + [self._q(name) for name in self.cfg.extra_field_names]
        with self._transaction() as conn:
            row = conn.execute(
                f"SELECT {', '.join(columns)} FROM {self.cfg.table(TABLE_NAME)} "
                f"WHERE username={self.cfg.placeholder}",
                (username,),
            ).fetchone()
        if row is None:
            return None
        return AdminAccount(*row[:5], extra=dict(zip(self.cfg.extra_field_names, row[5:])))

    def create_account(self, username: str, password_hash: str, extra: dict) -> None:
        p = self.cfg.placeholder
        columns = ["username", "password_hash", "is_first_login", "created_at", *self.cfg.extra_field_names]
        values = [username, password_hash, False, datetime.now(timezone.utc).isoformat()]
        values.extend(extra.get(name, "") for name in self.cfg.extra_field_names)
        with self._transaction(write=True) as conn:
            self._create_schema(conn)
            conn.execute(
                f"INSERT INTO {self.cfg.table(TABLE_NAME)} "
                f"({', '.join(self._q(name) for name in columns)}) "
                f"VALUES ({', '.join([p] * len(values))})",
                values,
            )

    def update_password(self, username: str, new_password_hash: str) -> bool:
        p = self.cfg.placeholder
        with self._transaction(write=True) as conn:
            result = conn.execute(
                f"UPDATE {self.cfg.table(TABLE_NAME)} SET password_hash={p} WHERE username={p}",
                (new_password_hash, username),
            )
            return result.rowcount > 0

    def update_password_if_current(self, username: str, current_hash: str, new_hash: str) -> bool:
        p = self.cfg.placeholder
        with self._transaction(write=True) as conn:
            result = conn.execute(
                f"UPDATE {self.cfg.table(TABLE_NAME)} SET password_hash={p} "
                f"WHERE username={p} AND password_hash={p}",
                (new_hash, username, current_hash),
            )
            return result.rowcount > 0

    def increment_failed_attempts(self, username: str) -> int:
        p = self.cfg.placeholder
        with self._transaction(write=True) as conn:
            if self.cfg.db_backend == "postgres":
                row = conn.execute(
                    f"UPDATE {self.cfg.table(TABLE_NAME)} SET failed_attempts=failed_attempts+1 "
                    f"WHERE username={p} RETURNING failed_attempts", (username,),
                ).fetchone()
            else:
                conn.execute(
                    f"UPDATE {self.cfg.table(TABLE_NAME)} SET failed_attempts=failed_attempts+1 "
                    f"WHERE username={p}", (username,),
                )
                row = conn.execute(
                    f"SELECT failed_attempts FROM {self.cfg.table(TABLE_NAME)} WHERE username={p}",
                    (username,),
                ).fetchone()
            return row[0] if row else 0

    def reset_failed_attempts(self, username: str) -> None:
        with self._transaction(write=True) as conn:
            conn.execute(
                f"UPDATE {self.cfg.table(TABLE_NAME)} SET failed_attempts=0 WHERE username={self.cfg.placeholder}",
                (username,),
            )

    def set_locked_until(self, username: str, locked_until: Optional[str]) -> None:
        p = self.cfg.placeholder
        with self._transaction(write=True) as conn:
            conn.execute(
                f"UPDATE {self.cfg.table(TABLE_NAME)} SET locked_until={p} WHERE username={p}",
                (locked_until, username),
            )


def get_repository(cfg: Any) -> AccountRepository:
    return AccountRepository(cfg)
