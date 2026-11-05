# QMS — Tkinter với SQLite hoặc PostgreSQL

Ứng dụng desktop gồm cổng khởi tạo Super Admin (`Khoi_Tao_Tai_Khoan.py`) và tiện ích đổi mật khẩu (`Quan_Ly_SuperAdmin.py`). SQLite phù hợp phát triển trên một máy; triển khai nhiều máy nên cấu hình các client dùng chung PostgreSQL qua mạng riêng và TLS.

## Yêu cầu và cài đặt

- Python 3.10 trở lên; bản cài Python trên Windows cần có Tcl/Tk để chạy Tkinter.
- PostgreSQL 14 trở lên khi chọn backend PostgreSQL.
- Driver Psycopg 3: `python -m pip install -r requirements.txt`.

Chạy kiểm thử: `python -m unittest discover -s tests -v`.

## Chạy SQLite cục bộ

Mặc định ứng dụng dùng SQLite tại `QMS_BASE_DIR/system_qms.db` (nếu không khai báo `QMS_BASE_DIR`, dùng thư mục chạy ứng dụng). Chạy:

```powershell
python .\Khoi_Tao_Tai_Khoan.py
python .\Quan_Ly_SuperAdmin.py
```

Tệp `rbac_seed.json` phải nằm cùng thư mục với các module Python, hoặc đặt `QMS_RBAC_SEED` tới một đường dẫn khác. Mật khẩu bootstrap tạm chỉ được giữ trong bộ nhớ và hiện một lần trên cửa sổ cài đặt; hãy lưu an toàn và đổi ngay khi được yêu cầu. Không có mật khẩu tạm nào được ghi vào log.

## Dùng chung PostgreSQL

Tạo database và schema trước bằng quy trình quản trị PostgreSQL của tổ chức. Cấp quyền tạo bảng/migration cho tài khoản triển khai riêng; tài khoản ứng dụng hằng ngày chỉ nên có quyền cần thiết trên các bảng, không dùng superuser hoặc tài khoản owner. Ví dụ biến môi trường (đây chỉ là tên biến, không phải thông tin xác thực):

```powershell
$env:QMS_DB_BACKEND = "postgres"
$env:QMS_PGHOST = "db.internal.example"
$env:QMS_PGPORT = "5432"
$env:QMS_PGDATABASE = "qms"
$env:QMS_PGUSER = "<tai-khoan-ung-dung>"
$env:QMS_PGPASSWORD = "<lay-tu-kho-bi-mat>"
$env:QMS_PGSCHEMA = "public"
$env:QMS_PGSSLMODE = "verify-full"
python .\Khoi_Tao_Tai_Khoan.py
```

Không ghi mật khẩu DB vào mã nguồn, README, tham số dòng lệnh hoặc log. Hãy cấp riêng một tài khoản/secret cho từng máy, lưu bằng secret manager hoặc cơ chế bảo vệ của hệ điều hành, giới hạn kết nối mạng theo máy và bật xác minh chứng thư TLS (`verify-full`) ở production. Không dùng chung thông tin đăng nhập quản trị DB. Lần bootstrap phải chạy bằng tài khoản có quyền tạo bảng và khởi tạo dữ liệu; sau đó nên chuyển sang tài khoản runtime quyền thấp hơn. Ứng dụng kiểm tra identifier schema/cột trước khi tạo SQL; giá trị người dùng vẫn được bind parameter.

Bootstrap tài khoản, seed role/permission, assignment Admin và cờ khóa cài đặt chạy trong một transaction. PostgreSQL dùng transaction-scoped advisory lock để tránh hai máy cùng bootstrap/seed; các khóa và ràng buộc duy nhất là lớp bảo vệ bổ sung. Seed chỉ thêm dữ liệu còn thiếu, không sửa các role/permission đã tồn tại.

## Phân quyền và giới hạn kiến trúc

Các kiểm tra RBAC trong ứng dụng chỉ điều khiển hành vi GUI/nghiệp vụ phía client. Khi một client kết nối trực tiếp với PostgreSQL bằng credential có quyền truy cập rộng, người nắm credential có thể gọi SQL trực tiếp hoặc sửa ứng dụng để bỏ qua RBAC phía client. **RBAC client-side không thể bảo vệ PostgreSQL khỏi chính một client có SQL credentials rộng.** Hạn chế quyền của tài khoản PostgreSQL đến mức tối thiểu; nếu cần cưỡng chế quyền theo từng người dùng hoặc tenant, dùng API tin cậy ở server hoặc chính sách DB (ví dụ role DB riêng/RLS, cấu hình xác thực và kiểm tra quyền phù hợp), thay vì coi kiểm tra trong Tkinter là ranh giới bảo mật.

Audit log đổi mật khẩu là JSON Lines cục bộ tại `QMS_BASE_DIR/logs/audit_superadmin.jsonl`; log không chứa mật khẩu hoặc hash. Triển khai nhiều máy cần cấu hình thu thập log riêng nếu cần audit tập trung. Quyền truy cập, chống sửa đổi và lưu trữ log tập trung phải được triển khai/quản trị bên ngoài ứng dụng desktop này.

## Cấu hình tùy chọn

| Biến | Mặc định | Ý nghĩa |
|---|---|---|
| `QMS_DB_BACKEND` | `sqlite` | `sqlite` hoặc `postgres` |
| `QMS_BASE_DIR` | thư mục hiện hành | Vị trí DB SQLite và log |
| `QMS_PGHOST`, `QMS_PGPORT` | `localhost`, `5432` | Máy chủ/cổng PostgreSQL |
| `QMS_PGDATABASE`, `QMS_PGUSER`, `QMS_PGPASSWORD` | không có | Database và credential bắt buộc cho PostgreSQL |
| `QMS_PGSCHEMA` | `public` | Tên schema PostgreSQL hợp lệ |
| `QMS_PGSSLMODE` | `verify-full` | Chế độ TLS của Psycopg |
| `QMS_PGCONNECT_TIMEOUT` | `10` | Thời gian chờ kết nối, giây |
| `QMS_EXTRA_FIELDS` | rỗng | Danh sách cột phụ, phân tách bằng dấu phẩy |
| `QMS_PBKDF2_ITERATIONS` | `600000` | Số vòng PBKDF2, từ 10.000 đến 2.000.000 |
| `QMS_MIN_PASSWORD_LEN` | `10` | Độ dài mật khẩu tối thiểu |
| `QMS_DEFAULT_ADMIN_USERNAME` | `admin` | Tên đăng nhập gợi ý cho lần bootstrap |
| `QMS_RBAC_SEED` | `rbac_seed.json` | Tên/đường dẫn tệp seed |
