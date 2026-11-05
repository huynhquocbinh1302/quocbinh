# -*- coding: utf-8 -*-
"""Giao diện Tkinter đổi mật khẩu Super Admin."""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
import tkinter as tk
from tkinter import messagebox, ttk

from account_repository import get_repository
from auth_utils import hash_password, verify_password
from config import AppConfig

FONT_FAMILY = "Segoe UI"
COLORS = {
    "bg_window": "#F3F5F9", "bg_card": "#FFFFFF", "bg_header": "#15223B",
    "primary": "#2F5CFF", "primary_hover": "#1E46DB", "text_main": "#1A1F2B",
    "text_muted": "#6B7280", "danger": "#DC2626", "border": "#E2E5EC",
}
logger = logging.getLogger(__name__)


def font(size: int, weight: str = "normal") -> tuple:
    return (FONT_FAMILY, size, weight)


def _write_audit(cfg: AppConfig, username: str, success: bool, reason: str) -> bool:
    try:
        cfg.ensure_log_dir()
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": "superadmin_password_change",
            "username": username[:200].replace("\n", "").replace("\r", ""),
            "success": success,
            "reason": reason,
            "actor": os.environ.get("USERNAME") or os.environ.get("USER") or "unknown",
        }
        with open(cfg.audit_log_path, "a", encoding="utf-8") as stream:
            stream.write(json.dumps(event, ensure_ascii=False) + "\n")
        return True
    except OSError as exc:
        logger.error("Không ghi được audit log (%s).", type(exc).__name__)
        return False


def _audit_failure_message() -> str:
    return "Không ghi được audit log; thao tác không được thực hiện."


def change_superadmin_password(
    cfg: AppConfig, username: str, current_password: str, new_password: str,
) -> tuple[bool, str]:
    if not username or not current_password or not new_password:
        if not _write_audit(cfg, username or "(trống)", False, "missing_input"):
            return False, _audit_failure_message()
        return False, "Vui lòng điền đầy đủ thông tin."
    if len(new_password) < cfg.min_password_length:
        if not _write_audit(cfg, username, False, "password_too_short"):
            return False, _audit_failure_message()
        return False, f"Mật khẩu mới phải có ít nhất {cfg.min_password_length} ký tự."
    if new_password == current_password:
        if not _write_audit(cfg, username, False, "password_unchanged"):
            return False, _audit_failure_message()
        return False, "Mật khẩu mới không được trùng mật khẩu hiện tại."
    try:
        repository = get_repository(cfg)
        account = repository.get_by_username(username)
        if account is None:
            if not _write_audit(cfg, username, False, "account_not_found"):
                return False, _audit_failure_message()
            return False, "Không tìm thấy tài khoản."
        if not verify_password(current_password, account.password_hash):
            if not _write_audit(cfg, username, False, "current_password_invalid"):
                return False, _audit_failure_message()
            return False, "Mật khẩu hiện tại không chính xác. Yêu cầu bị từ chối."
        replacement = hash_password(new_password, cfg.pbkdf2_iterations)
        if not repository.update_password_if_current(username, account.password_hash, replacement):
            if not _write_audit(cfg, username, False, "concurrent_password_change"):
                return False, _audit_failure_message()
            return False, "Mật khẩu đã thay đổi đồng thời. Vui lòng xác thực lại và thử lại."
        if not _write_audit(cfg, username, True, "password_changed"):
            return True, "Mật khẩu đã đổi, nhưng không ghi được audit log. Hãy báo quản trị viên."
        return True, f"Cập nhật mật khẩu cho tài khoản '{username}' thành công."
    except Exception as exc:
        logger.error("Đổi mật khẩu thất bại do lỗi %s.", type(exc).__name__)
        if not _write_audit(cfg, username, False, "storage_or_audit_error"):
            return False, "Không thể ghi audit log; không thể xác nhận thao tác."
        return False, "Không thể hoàn tất do lỗi lưu trữ. Không có dữ liệu nhạy cảm nào được ghi log."


class PasswordField(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent, style="Card.TFrame")
        self.visible = False
        self.entry = ttk.Entry(self, font=font(10), show="•", style="Modern.TEntry")
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=6)
        self.toggle = tk.Label(self, text="Hiện", font=font(8, "bold"), fg=COLORS["primary"],
                               bg=COLORS["bg_card"], cursor="hand2")
        self.toggle.pack(side=tk.RIGHT, padx=(8, 0))
        self.toggle.bind("<Button-1>", self._toggle)

    def _toggle(self, _event=None) -> None:
        self.visible = not self.visible
        self.entry.config(show="" if self.visible else "•")
        self.toggle.config(text="Ẩn" if self.visible else "Hiện")

    def get(self) -> str:
        return self.entry.get()


class ChangePasswordApp:
    def __init__(self, root: tk.Tk, cfg: AppConfig):
        self.root, self.cfg = root, cfg
        root.title(f"{cfg.app_title} · Đổi mật khẩu Super Admin")
        root.geometry("480x480")
        root.minsize(480, 480)
        root.configure(bg=COLORS["bg_window"])
        style = ttk.Style(root)
        style.theme_use("clam")
        style.configure("Card.TFrame", background=COLORS["bg_card"])
        style.configure("Modern.TEntry", fieldbackground=COLORS["bg_card"], bordercolor=COLORS["border"],
                        lightcolor=COLORS["border"], darkcolor=COLORS["border"], borderwidth=1,
                        relief="solid", padding=6)
        self._build_ui()

    def _build_ui(self) -> None:
        header = tk.Frame(self.root, bg=COLORS["bg_header"], height=78)
        header.pack(fill=tk.X)
        header.pack_propagate(False)
        tk.Label(header, text="🔐  ĐỔI MẬT KHẨU SUPER ADMIN", bg=COLORS["bg_header"],
                 fg="white", font=font(14, "bold")).pack(anchor="w", padx=24, pady=(16, 0))
        tk.Label(header, text="Yêu cầu xác thực mật khẩu hiện tại · Có ghi audit log",
                 bg=COLORS["bg_header"], fg="#9FB3D9", font=font(9)).pack(anchor="w", padx=24)
        card = tk.Frame(self.root, bg=COLORS["bg_card"], highlightbackground=COLORS["border"],
                        highlightthickness=1)
        card.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        body = tk.Frame(card, bg=COLORS["bg_card"])
        body.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        self._label(body, "Tên đăng nhập Super Admin")
        self.ent_username = ttk.Entry(body, font=font(10), style="Modern.TEntry")
        self.ent_username.pack(fill=tk.X, ipady=6, pady=(4, 14))
        self.ent_username.insert(0, cfg.default_admin_username)
        self._label(body, "Mật khẩu hiện tại (bắt buộc để xác thực)")
        self.ent_current = PasswordField(body)
        self.ent_current.pack(fill=tk.X, pady=(4, 14))
        self._label(body, f"Mật khẩu mới (tối thiểu {cfg.min_password_length} ký tự)")
        self.ent_new = PasswordField(body)
        self.ent_new.pack(fill=tk.X, pady=(4, 14))
        self._label(body, "Xác nhận mật khẩu mới")
        self.ent_confirm = PasswordField(body)
        self.ent_confirm.pack(fill=tk.X, pady=(4, 22))
        tk.Button(body, text="Xác thực & Đổi mật khẩu  →", bg=COLORS["primary"], fg="white",
                  font=font(10, "bold"), relief=tk.FLAT, activebackground=COLORS["primary_hover"],
                  bd=0, padx=16, pady=10, cursor="hand2", command=self._on_submit).pack(fill=tk.X)
        tk.Label(body, text="Mọi thao tác thành công hoặc thất bại đều được ghi vào audit log.",
                 bg=COLORS["bg_card"], fg=COLORS["text_muted"], font=font(8),
                 wraplength=380, justify=tk.LEFT).pack(fill=tk.X, pady=(12, 0))

    @staticmethod
    def _label(parent, text: str) -> None:
        tk.Label(parent, text=text, bg=COLORS["bg_card"], fg=COLORS["text_main"],
                 font=font(9, "bold"), anchor="w").pack(fill=tk.X)

    def _on_submit(self) -> None:
        username = self.ent_username.get().strip()
        current = self.ent_current.get()
        new = self.ent_new.get()
        if new != self.ent_confirm.get():
            messagebox.showerror("Lỗi xác nhận", "Mật khẩu xác nhận không khớp với mật khẩu mới.")
            return
        success, message = change_superadmin_password(self.cfg, username, current, new)
        if success:
            messagebox.showinfo("Thành công", message)
            for field in (self.ent_current, self.ent_new, self.ent_confirm):
                field.entry.delete(0, tk.END)
        else:
            messagebox.showerror("Yêu cầu bị từ chối", message)


def main() -> None:
    root = tk.Tk()
    ChangePasswordApp(root, AppConfig())
    root.mainloop()


if __name__ == "__main__":
    main()
