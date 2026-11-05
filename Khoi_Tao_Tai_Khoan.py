# -*- coding: utf-8 -*-
"""Giao diện Tkinter khởi tạo tài khoản quản trị viên một lần."""
from __future__ import annotations

import logging
import tkinter as tk
from tkinter import messagebox, ttk

from account_repository import get_repository
from auth_utils import generate_temp_password, hash_password
from config import AppConfig
from rbac_repository import load_seed_file

FONT_FAMILY = "Segoe UI"
COLORS = {
    "bg_window": "#F3F5F9", "bg_card": "#FFFFFF", "bg_header": "#15223B",
    "primary": "#2F5CFF", "primary_hover": "#1E46DB", "text_main": "#1A1F2B",
    "text_muted": "#6B7280", "success": "#16A34A", "danger": "#DC2626",
    "warning_bg": "#FFF7E6", "warning_border": "#F2B705", "border": "#E2E5EC",
}
FRIENDLY_LABELS = {
    "email": "Địa chỉ email", "full_name": "Họ và tên", "department": "Phòng ban",
    "phone": "Số điện thoại", "role": "Vai trò",
}
logger = logging.getLogger(__name__)


def font(size: int, weight: str = "normal") -> tuple:
    return (FONT_FAMILY, size, weight)


def friendly_label(name: str) -> str:
    return FRIENDLY_LABELS.get(name, name.replace("_", " ").capitalize())


class PasswordEntry(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent, style="Card.TFrame")
        self.visible = False
        self.entry = ttk.Entry(self, font=font(10), show="•", style="Modern.TEntry")
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=6)
        self.toggle_btn = tk.Label(self, text="Hiện", font=font(8, "bold"), fg=COLORS["primary"],
                                   bg=COLORS["bg_card"], cursor="hand2")
        self.toggle_btn.pack(side=tk.RIGHT, padx=(8, 0))
        self.toggle_btn.bind("<Button-1>", self._toggle)

    def _toggle(self, _event=None) -> None:
        self.visible = not self.visible
        self.entry.config(show="" if self.visible else "•")
        self.toggle_btn.config(text="Ẩn" if self.visible else "Hiện")

    def get(self) -> str:
        return self.entry.get()

    def focus(self) -> None:
        self.entry.focus_set()


class SetupApp:
    def __init__(self, root: tk.Tk, cfg: AppConfig):
        self.root, self.cfg = root, cfg
        self.repo = get_repository(cfg)
        self.temp_password = generate_temp_password()
        self.extra_entries: dict[str, ttk.Entry] = {}
        root.title(f"{cfg.app_title} · Khởi tạo Hạ tầng & Tài khoản Gốc")
        root.geometry("560x720")
        root.minsize(560, 640)
        root.configure(bg=COLORS["bg_window"])
        self._setup_styles()
        try:
            cfg.ensure_log_dir()
            self.repo.initialize()
            if self.repo.is_installed():
                messagebox.showwarning("Đã khóa cài đặt", "Hệ thống đã được khởi tạo; không thể chạy lại.")
                root.destroy()
                return
        except Exception as exc:
            logger.error("Khởi tạo kết nối thất bại (%s).", type(exc).__name__)
            messagebox.showerror(
                "Lỗi lưu trữ",
                "Không thể khởi tạo cơ sở dữ liệu. Kiểm tra cấu hình và kết nối.",
            )
            root.destroy()
            return
        self._build_ui()

    def _setup_styles(self) -> None:
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure("Card.TFrame", background=COLORS["bg_card"])
        style.configure("Window.TFrame", background=COLORS["bg_window"])
        style.configure("Modern.TEntry", fieldbackground=COLORS["bg_card"], bordercolor=COLORS["border"],
                        lightcolor=COLORS["border"], darkcolor=COLORS["border"], borderwidth=1,
                        relief="solid", padding=6)

    def _build_ui(self) -> None:
        header = tk.Frame(self.root, bg=COLORS["bg_header"], height=86)
        header.pack(fill=tk.X)
        header.pack_propagate(False)
        tk.Label(header, text="⚙  KHỞI TẠO TÀI KHOẢN GỐC", bg=COLORS["bg_header"],
                 fg="white", font=font(15, "bold")).pack(anchor="w", padx=28, pady=(16, 0))
        tk.Label(header, text=f"Super Admin Bootstrap · {self.cfg.app_subtitle}",
                 bg=COLORS["bg_header"], fg="#9FB3D9", font=font(9)).pack(anchor="w", padx=28)
        canvas = tk.Canvas(self.root, bg=COLORS["bg_window"], highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.root, orient="vertical", command=canvas.yview)
        outer = tk.Frame(canvas, bg=COLORS["bg_window"])
        outer.bind("<Configure>", lambda _e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=outer, anchor="nw", width=560)
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        pad = tk.Frame(outer, bg=COLORS["bg_window"])
        pad.pack(fill=tk.BOTH, expand=True, padx=24, pady=20)
        warning = tk.Frame(pad, bg=COLORS["warning_bg"], highlightbackground=COLORS["warning_border"],
                           highlightthickness=1)
        warning.pack(fill=tk.X, pady=(0, 18))
        tk.Label(warning, text="🔑  THÔNG TIN ĐĂNG NHẬP TẠM THỜI — chỉ hiển thị một lần",
                 bg=COLORS["warning_bg"], fg="#8A6100", font=font(9, "bold"),
                 anchor="w").pack(fill=tk.X, padx=16, pady=(12, 6))
        tk.Label(warning, text=f"Tên đăng nhập: {self.cfg.default_admin_username}",
                 bg=COLORS["warning_bg"], fg=COLORS["text_main"], font=font(10, "bold")).pack(anchor="w", padx=16)
        self.lbl_temp_pass_value = tk.Label(warning, text=self.temp_password,
                                            bg=COLORS["warning_bg"], fg=COLORS["danger"],
                                            font=("Consolas", 12, "bold"))
        self.lbl_temp_pass_value.pack(anchor="w", padx=16, pady=(0, 10))
        tk.Label(warning, text="Mật khẩu tạm chỉ được giữ trong bộ nhớ ứng dụng, không ghi vào log.",
                 bg=COLORS["warning_bg"], fg="#8A6100", font=font(8),
                 anchor="w").pack(fill=tk.X, padx=16, pady=(0, 12))
        card = tk.Frame(pad, bg=COLORS["bg_card"], highlightbackground=COLORS["border"], highlightthickness=1)
        card.pack(fill=tk.BOTH, expand=True)
        form = tk.Frame(card, bg=COLORS["bg_card"])
        form.pack(fill=tk.BOTH, expand=True, padx=24, pady=22)
        self._field_label(form, "Tên đăng nhập Super Admin")
        self.ent_user = ttk.Entry(form, font=font(10), style="Modern.TEntry")
        self.ent_user.pack(fill=tk.X, ipady=6, pady=(4, 16))
        self.ent_user.insert(0, self.cfg.default_admin_username)
        for name in self.cfg.extra_field_names:
            self._field_label(form, friendly_label(name))
            entry = ttk.Entry(form, font=font(10), style="Modern.TEntry")
            entry.pack(fill=tk.X, ipady=6, pady=(4, 16))
            self.extra_entries[name] = entry
        self._field_label(form, "Mật khẩu tạm thời")
        self.ent_pass_old = PasswordEntry(form)
        self.ent_pass_old.pack(fill=tk.X, pady=(4, 16))
        self._field_label(form, f"Mật khẩu chính thức mới (tối thiểu {cfg.min_password_length} ký tự)")
        self.ent_pass_new = PasswordEntry(form)
        self.ent_pass_new.pack(fill=tk.X, pady=(4, 4))
        self.lbl_strength = tk.Label(form, text="", bg=COLORS["bg_card"], font=font(8), anchor="w")
        self.lbl_strength.pack(fill=tk.X, pady=(0, 16))
        self.ent_pass_new.entry.bind("<KeyRelease>", self._update_strength_hint)
        self._field_label(form, "Xác nhận mật khẩu mới")
        self.ent_pass_confirm = PasswordEntry(form)
        self.ent_pass_confirm.pack(fill=tk.X, pady=(4, 24))
        tk.Button(form, text="Xác nhận & Khóa Cổng Cài Đặt  →", bg=COLORS["primary"], fg="white",
                  font=font(10, "bold"), relief=tk.FLAT, activebackground=COLORS["primary_hover"],
                  bd=0, padx=18, pady=10, cursor="hand2", command=self._on_submit).pack(fill=tk.X)
        self.ent_pass_old.focus()

    @staticmethod
    def _field_label(parent, text: str) -> None:
        tk.Label(parent, text=text, bg=COLORS["bg_card"], fg=COLORS["text_main"],
                 font=font(9, "bold"), anchor="w").pack(fill=tk.X)

    def _update_strength_hint(self, _event=None) -> None:
        value = self.ent_pass_new.get()
        score = sum((
            len(value) >= self.cfg.min_password_length, any(char.isdigit() for char in value),
            any(char.isupper() for char in value), any(not char.isalnum() for char in value),
        ))
        if not value:
            text, color = "", COLORS["text_muted"]
        elif score <= 1:
            text, color = "Độ mạnh: Yếu — nên thêm số, chữ hoa, ký tự đặc biệt", COLORS["danger"]
        elif score <= 3:
            text, color = "Độ mạnh: Trung bình", "#B45309"
        else:
            text, color = "Độ mạnh: Mạnh ✓", COLORS["success"]
        self.lbl_strength.config(text=text, fg=color)

    def _on_submit(self) -> None:
        username = self.ent_user.get().strip()
        old, password, confirm = self.ent_pass_old.get(), self.ent_pass_new.get(), self.ent_pass_confirm.get()
        extra = {name: entry.get().strip() for name, entry in self.extra_entries.items()}
        if not username or not old or not password or not confirm:
            messagebox.showerror("Thiếu thông tin", "Vui lòng điền đầy đủ tất cả các trường.")
            return
        if any(not value for value in extra.values()):
            messagebox.showerror("Thiếu thông tin", "Vui lòng điền đầy đủ các trường bổ sung.")
            return
        if old != self.temp_password:
            messagebox.showerror("Lỗi xác thực", "Mật khẩu tạm thời không chính xác.")
            return
        if password != confirm:
            messagebox.showerror("Lỗi xác nhận", "Mật khẩu xác nhận không khớp.")
            return
        if len(password) < self.cfg.min_password_length or password == self.temp_password:
            messagebox.showerror(
                "Mật khẩu không hợp lệ",
                f"Mật khẩu mới phải có ít nhất {self.cfg.min_password_length} ký tự và khác mật khẩu tạm.",
            )
            return
        try:
            seed = load_seed_file(self.cfg.rbac_seed_path)
            self.repo.bootstrap_account(username, hash_password(password, self.cfg.pbkdf2_iterations), extra, seed)
        except ValueError as exc:
            logger.warning("Yêu cầu bootstrap bị từ chối (%s).", type(exc).__name__)
            messagebox.showerror("Không thể khởi tạo", str(exc))
            return
        except Exception as exc:
            logger.error("Bootstrap thất bại (%s).", type(exc).__name__)
            messagebox.showerror(
                "Lỗi lưu trữ dữ liệu",
                "Không thể khởi tạo tài khoản. Kiểm tra cấu hình, seed và kết nối cơ sở dữ liệu.",
            )
            return
        self.temp_password = ""
        self.lbl_temp_pass_value.config(text="")
        messagebox.showinfo(
            "Khởi tạo thành công",
            "Tài khoản Super Admin đã được tạo và cổng cài đặt đã khóa.",
        )
        self.root.destroy()


def main() -> None:
    root = tk.Tk()
    SetupApp(root, AppConfig())
    root.mainloop()


if __name__ == "__main__":
    main()
