"""Kho RBAC giao dịch, hỗ trợ SQLite và PostgreSQL."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class Department:
    name: str
    description: str = ""


@dataclass
class Permission:
    code: str
    name: str
    module: str


@dataclass
class Role:
    name: str
    permission_codes: list[str] = field(default_factory=list)


@dataclass
class Assignment:
    username: str
    role_name: str
    department_name: str
    assigned_at: str
    assigned_by: str = ""
    is_active: bool = True


def validate_seed(seed: Any) -> dict[str, list[dict[str, Any]]]:
    if not isinstance(seed, dict):
        raise ValueError("Tệp seed RBAC phải là một đối tượng JSON.")
    definitions = {
        "departments": ("name", "description"),
        "permissions": ("code", "name", "module"),
        "roles": ("name", "permissions"),
    }
    validated: dict[str, list[dict[str, Any]]] = {}
    for collection, fields in definitions.items():
        items = seed.get(collection)
        if not isinstance(items, list):
            raise ValueError(f"Trường seed '{collection}' phải là một mảng.")
        validated[collection] = []
        seen: set[str] = set()
        for item in items:
            if not isinstance(item, dict):
                raise ValueError(f"Mỗi mục trong '{collection}' phải là đối tượng.")
            key = fields[0]
            value = item.get(key)
            if not isinstance(value, str) or not value.strip() or len(value) > 200:
                raise ValueError(f"Seed có trường '{key}' không hợp lệ.")
            if value in seen:
                raise ValueError(f"Seed có '{key}' bị trùng.")
            seen.add(value)
            record: dict[str, Any] = {key: value}
            for name in fields[1:]:
                field_value = item.get(name, [] if name == "permissions" else "")
                if name == "permissions":
                    if not isinstance(field_value, list) or any(
                        not isinstance(code, str) or not code.strip() for code in field_value
                    ):
                        raise ValueError("Danh sách quyền của role chứa mã không hợp lệ.")
                    if len(set(field_value)) != len(field_value):
                        raise ValueError("Role có mã quyền bị trùng.")
                    record[name] = list(field_value)
                else:
                    if not isinstance(field_value, str) or len(field_value) > 2000:
                        raise ValueError(f"Seed có trường '{name}' không hợp lệ.")
                    record[name] = field_value
            validated[collection].append(record)
    permission_codes = {item["code"] for item in validated["permissions"]}
    if any(not set(role["permissions"]).issubset(permission_codes) for role in validated["roles"]):
        raise ValueError("Seed có role tham chiếu đến permission không tồn tại.")
    return validated


def _transaction(cfg: Any, write: bool = False):
    class Transaction:
        def __enter__(self):
            self.conn = cfg.connect()
            if cfg.db_backend == "sqlite" and write:
                self.conn.execute("BEGIN IMMEDIATE")
            return self.conn

        def __exit__(self, exc_type, exc, tb):
            try:
                self.conn.rollback() if exc_type else self.conn.commit()
            finally:
                self.conn.close()
            return False
    return Transaction()


def _bootstrap_lock(conn: Any, cfg: Any, key: str) -> None:
    if cfg.db_backend == "postgres":
        conn.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (f"qms:{cfg.postgres_schema}:{key}",))


def initialize_rbac_schema(conn: Any, cfg: Any) -> None:
    dept, perm, role, rp, assignment = (
        cfg.table("departments"), cfg.table("permissions"), cfg.table("roles"),
        cfg.table("role_permissions"), cfg.table("user_assignments"),
    )
    conn.execute(f"CREATE TABLE IF NOT EXISTS {dept} (name TEXT PRIMARY KEY, description TEXT NOT NULL DEFAULT '')")
    conn.execute(f"CREATE TABLE IF NOT EXISTS {perm} (code TEXT PRIMARY KEY, name TEXT NOT NULL, module TEXT NOT NULL)")
    conn.execute(f"CREATE TABLE IF NOT EXISTS {role} (name TEXT PRIMARY KEY)")
    conn.execute(
        f"""CREATE TABLE IF NOT EXISTS {rp} (
            role_name TEXT NOT NULL REFERENCES {role}(name) ON DELETE CASCADE,
            permission_code TEXT NOT NULL REFERENCES {perm}(code) ON DELETE CASCADE,
            PRIMARY KEY(role_name, permission_code))"""
    )
    active_type = "INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0,1))" if cfg.db_backend == "sqlite" else "BOOLEAN NOT NULL DEFAULT TRUE"
    conn.execute(
        f"""CREATE TABLE IF NOT EXISTS {assignment} (
            username TEXT NOT NULL,
            role_name TEXT NOT NULL REFERENCES {role}(name),
            department_name TEXT NOT NULL REFERENCES {dept}(name),
            assigned_at TEXT NOT NULL, assigned_by TEXT NOT NULL DEFAULT '',
            is_active {active_type},
            PRIMARY KEY(username, role_name, department_name))"""
    )


def seed_on_connection(conn: Any, cfg: Any, seed: Any) -> None:
    seed = validate_seed(seed)
    p = cfg.placeholder
    dept, perm, role, rp = (
        cfg.table("departments"), cfg.table("permissions"), cfg.table("roles"),
        cfg.table("role_permissions"),
    )
    for item in seed["departments"]:
        conn.execute(
            f"INSERT INTO {dept}(name,description) VALUES ({p},{p}) ON CONFLICT(name) DO NOTHING",
            (item["name"], item["description"]),
        )
    for item in seed["permissions"]:
        conn.execute(
            f"INSERT INTO {perm}(code,name,module) VALUES ({p},{p},{p}) ON CONFLICT(code) DO NOTHING",
            (item["code"], item["name"], item["module"]),
        )
    for item in seed["roles"]:
        conn.execute(f"INSERT INTO {role}(name) VALUES ({p}) ON CONFLICT(name) DO NOTHING", (item["name"],))
        for code in item["permissions"]:
            conn.execute(
                f"INSERT INTO {rp}(role_name,permission_code) VALUES ({p},{p}) "
                "ON CONFLICT(role_name,permission_code) DO NOTHING",
                (item["name"], code),
            )


class RBACRepository:
    def __init__(self, cfg: Any):
        self.cfg = cfg

    def initialize(self) -> None:
        with _transaction(self.cfg, write=True) as conn:
            initialize_rbac_schema(conn, self.cfg)

    def is_empty(self) -> bool:
        with _transaction(self.cfg) as conn:
            count = conn.execute(f"SELECT COUNT(*) FROM {self.cfg.table('permissions')}").fetchone()[0]
            return count == 0

    def seed_from_dict(self, seed: dict) -> None:
        seed = validate_seed(seed)
        with _transaction(self.cfg, write=True) as conn:
            initialize_rbac_schema(conn, self.cfg)
            _bootstrap_lock(conn, self.cfg, "rbac-seed")
            seed_on_connection(conn, self.cfg, seed)

    def list_departments(self) -> list[Department]:
        with _transaction(self.cfg) as conn:
            rows = conn.execute(f"SELECT name,description FROM {self.cfg.table('departments')} ORDER BY name").fetchall()
        return [Department(*row) for row in rows]

    def list_permissions(self) -> list[Permission]:
        with _transaction(self.cfg, write=True) as conn:
            rows = conn.execute(f"SELECT code,name,module FROM {self.cfg.table('permissions')} ORDER BY module,code").fetchall()
        return [Permission(*row) for row in rows]

    def list_roles(self) -> list[Role]:
        with _transaction(self.cfg, write=True) as conn:
            rows = conn.execute(
                f"""SELECT r.name,rp.permission_code FROM {self.cfg.table('roles')} r
                    LEFT JOIN {self.cfg.table('role_permissions')} rp ON rp.role_name=r.name
                    ORDER BY r.name,rp.permission_code"""
            ).fetchall()
        roles: dict[str, list[str]] = {}
        for name, code in rows:
            roles.setdefault(name, [])
            if code is not None:
                roles[name].append(code)
        return [Role(name, codes) for name, codes in roles.items()]

    def assign_user(self, username: str, role_name: str, department_name: str, assigned_by: str = "") -> None:
        p = self.cfg.placeholder
        now = datetime.now(timezone.utc).isoformat()
        with _transaction(self.cfg) as conn:
            conn.execute(
                f"""INSERT INTO {self.cfg.table('user_assignments')}
                    (username,role_name,department_name,assigned_at,assigned_by,is_active)
                    VALUES ({p},{p},{p},{p},{p},TRUE)
                    ON CONFLICT(username,role_name,department_name) DO UPDATE SET
                    assigned_at=excluded.assigned_at,assigned_by=excluded.assigned_by,is_active=TRUE""",
                (username, role_name, department_name, now, assigned_by),
            )

    def revoke_assignment(self, username: str, role_name: str, department_name: str) -> bool:
        p = self.cfg.placeholder
        with _transaction(self.cfg) as conn:
            result = conn.execute(
                f"UPDATE {self.cfg.table('user_assignments')} SET is_active=FALSE "
                f"WHERE username={p} AND role_name={p} AND department_name={p}",
                (username, role_name, department_name),
            )
            return result.rowcount > 0

    def list_user_assignments(self, username: str) -> list[Assignment]:
        p = self.cfg.placeholder
        with _transaction(self.cfg) as conn:
            rows = conn.execute(
                f"""SELECT username,role_name,department_name,assigned_at,assigned_by,is_active
                    FROM {self.cfg.table('user_assignments')} WHERE username={p} AND is_active=TRUE
                    ORDER BY department_name,role_name""",
                (username,),
            ).fetchall()
        return [Assignment(*row) for row in rows]

    def user_has_permission(self, username: str, permission_code: str) -> bool:
        p = self.cfg.placeholder
        with _transaction(self.cfg) as conn:
            row = conn.execute(
                f"""SELECT 1 FROM {self.cfg.table('user_assignments')} ua
                    JOIN {self.cfg.table('role_permissions')} rp ON rp.role_name=ua.role_name
                    WHERE ua.username={p} AND ua.is_active=TRUE AND rp.permission_code={p} LIMIT 1""",
                (username, permission_code),
            ).fetchone()
        return row is not None


def get_rbac_repository(cfg: Any) -> RBACRepository:
    return RBACRepository(cfg)


def load_seed_file(seed_path: str) -> dict:
    with Path(seed_path).open("r", encoding="utf-8") as file:
        return validate_seed(json.load(file))


def ensure_rbac_seeded(cfg: Any) -> RBACRepository:
    repo = get_rbac_repository(cfg)
    repo.initialize()
    seed = load_seed_file(cfg.rbac_seed_path)
    with _transaction(cfg, write=True) as conn:
        initialize_rbac_schema(conn, cfg)
        _bootstrap_lock(conn, cfg, "rbac-seed")
        count = conn.execute(f"SELECT COUNT(*) FROM {cfg.table('permissions')}").fetchone()[0]
        if count == 0:
            seed_on_connection(conn, cfg, seed)
    return repo
