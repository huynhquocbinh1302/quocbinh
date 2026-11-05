"""Cấu hình được kiểm tra cho SQLite cục bộ và PostgreSQL dùng chung."""
from __future__ import annotations

import os
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")


def quote_identifier(value: str) -> str:
    """Chỉ chấp nhận SQL identifier hợp lệ, không nhận biểu thức SQL tùy ý."""
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError("Tên định danh SQL trong cấu hình không hợp lệ.")
    return f'"{value}"'


def _env_list(key: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in os.environ.get(key, "").split(",") if part.strip())


@dataclass(frozen=True)
class AppConfig:
    app_title: str = field(default_factory=lambda: os.environ.get("QMS_APP_TITLE", "QMS 17043"))
    app_subtitle: str = field(default_factory=lambda: os.environ.get("QMS_APP_SUBTITLE", "Hệ thống QMS ISO/IEC 17043:2023"))
    base_dir: str = field(default_factory=lambda: os.environ.get("QMS_BASE_DIR", os.getcwd()))
    db_backend: str = field(default_factory=lambda: os.environ.get("QMS_DB_BACKEND", "sqlite").lower())
    db_filename: str = field(default_factory=lambda: os.environ.get("QMS_DB_FILENAME", "system_qms.db"))
    extra_field_names: tuple[str, ...] = field(default_factory=lambda: _env_list("QMS_EXTRA_FIELDS"))
    log_dirname: str = field(default_factory=lambda: os.environ.get("QMS_LOG_DIR", "logs"))
    audit_log_filename: str = field(default_factory=lambda: os.environ.get("QMS_AUDIT_LOG", "audit_superadmin.jsonl"))
    pbkdf2_iterations: int = field(default_factory=lambda: int(os.environ.get("QMS_PBKDF2_ITERATIONS", "600000")))
    min_password_length: int = field(default_factory=lambda: int(os.environ.get("QMS_MIN_PASSWORD_LEN", "10")))
    default_admin_username: str = field(default_factory=lambda: os.environ.get("QMS_DEFAULT_ADMIN_USERNAME", "admin"))
    rbac_seed_filename: str = field(default_factory=lambda: os.environ.get("QMS_RBAC_SEED", "rbac_seed.json"))
    postgres_host: str = field(default_factory=lambda: os.environ.get("QMS_PGHOST", "localhost"))
    postgres_port: int = field(default_factory=lambda: int(os.environ.get("QMS_PGPORT", "5432")))
    postgres_database: str = field(default_factory=lambda: os.environ.get("QMS_PGDATABASE", ""))
    postgres_user: str = field(default_factory=lambda: os.environ.get("QMS_PGUSER", ""))
    postgres_password: str = field(default_factory=lambda: os.environ.get("QMS_PGPASSWORD", ""), repr=False)
    postgres_schema: str = field(default_factory=lambda: os.environ.get("QMS_PGSCHEMA", "public"))
    postgres_sslmode: str = field(default_factory=lambda: os.environ.get("QMS_PGSSLMODE", "verify-full"))
    postgres_connect_timeout: int = field(default_factory=lambda: int(os.environ.get("QMS_PGCONNECT_TIMEOUT", "10")))

    def __post_init__(self) -> None:
        if self.db_backend not in {"sqlite", "postgres"}:
            raise ValueError("QMS_DB_BACKEND phải là 'sqlite' hoặc 'postgres'.")
        if not 10_000 <= self.pbkdf2_iterations <= 2_000_000:
            raise ValueError("QMS_PBKDF2_ITERATIONS phải nằm trong khoảng 10000..2000000.")
        if not 1 <= self.min_password_length <= 1024:
            raise ValueError("QMS_MIN_PASSWORD_LEN phải nằm trong khoảng 1..1024.")
        if not 1 <= self.postgres_port <= 65535 or self.postgres_connect_timeout < 1:
            raise ValueError("Cổng PostgreSQL hoặc thời gian chờ kết nối không hợp lệ.")
        quote_identifier(self.postgres_schema)
        reserved = {"id", "username", "password_hash", "is_first_login", "created_at", "failed_attempts", "locked_until"}
        seen: set[str] = set()
        for name in self.extra_field_names:
            quote_identifier(name)
            if name.lower() in reserved or name.lower() in seen:
                raise ValueError("QMS_EXTRA_FIELDS có trường trùng hoặc trùng tên dành riêng.")
            seen.add(name.lower())
        if self.db_backend == "postgres":
            if not self.postgres_database or not self.postgres_user or not self.postgres_password:
                raise ValueError("PostgreSQL cần QMS_PGDATABASE, QMS_PGUSER và QMS_PGPASSWORD.")
            if self.postgres_sslmode not in {"disable", "allow", "prefer", "require", "verify-ca", "verify-full"}:
                raise ValueError("QMS_PGSSLMODE không hợp lệ.")

    @property
    def db_path(self) -> str:
        return str(Path(self.base_dir) / self.db_filename)

    @property
    def log_dir_path(self) -> str:
        return str(Path(self.base_dir) / self.log_dirname)

    @property
    def audit_log_path(self) -> str:
        return str(Path(self.log_dir_path) / self.audit_log_filename)

    @property
    def rbac_seed_path(self) -> str:
        path = Path(self.rbac_seed_filename)
        return str(path if path.is_absolute() else Path(__file__).resolve().parent / path)

    @property
    def placeholder(self) -> str:
        return "?" if self.db_backend == "sqlite" else "%s"

    def table(self, name: str) -> str:
        quoted = quote_identifier(name)
        return quoted if self.db_backend == "sqlite" else f"{quote_identifier(self.postgres_schema)}.{quoted}"

    def connect(self) -> Any:
        if self.db_backend == "sqlite":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(self.db_path, timeout=15)
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=15000")
            return conn
        try:
            import psycopg
        except ImportError as exc:
            raise RuntimeError("Cài driver PostgreSQL bằng lệnh: pip install -r requirements.txt") from exc
        return psycopg.connect(
            host=self.postgres_host, port=self.postgres_port, dbname=self.postgres_database,
            user=self.postgres_user, password=self.postgres_password, sslmode=self.postgres_sslmode,
            connect_timeout=self.postgres_connect_timeout,
        )

    def ensure_log_dir(self) -> None:
        Path(self.log_dir_path).mkdir(parents=True, exist_ok=True)
