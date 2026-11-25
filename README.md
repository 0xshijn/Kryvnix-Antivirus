# Kryvnix Antivirus

<p align="center">
  <strong>Modern Windows Endpoint Protection built with C# / .NET 10 / WPF (MVVM), SQLite, LiveCharts2, AES-256-GCM Quarantine Vault, Ed25519 Signature Updates & C++20 Named Pipe IPC.</strong>
</p>

<p align="center">
  <img alt=".NET 10" src="https://img.shields.io/badge/.NET-10.0-512BD4?style=flat-square&logo=dotnet" />
  <img alt="WPF Windows" src="https://img.shields.io/badge/Platform-Windows%2010%2F11%20x64-0078D6?style=flat-square&logo=windows" />
  <img alt="SQLite" src="https://img.shields.io/badge/Database-SQLite%20%2B%20PostgreSQL-003B57?style=flat-square&logo=sqlite" />
  <img alt="Encryption" src="https://img.shields.io/badge/Security-AES--256--GCM%20%7C%20Ed25519%20%7C%20PBKDF2-22C55E?style=flat-square" />
</p>

---

## Giao diện ứng dụng

### Tổng quan (Dashboard)
![Kryvnix Antivirus Dashboard](docs/images/dashboard_preview.png)

### Đăng ký & Quản lý tài khoản (PBKDF2-SHA256)
![Kryvnix Antivirus Register Modal](docs/images/register_modal_preview.png)

---

## Tính năng nổi bật

- **Giao diện Fluent Dark chuẩn Windows 11**: Thanh tiêu đề tùy biến (`WindowChrome`), hỗ trợ Native Snap/Resize, tự căn theo DPI (`100%–200%`), thanh điều hướng Sidebar thu gọn mượt (`240px ↔ 72px`) và thu nhỏ xuống **System Tray** không ngắt bảo vệ nền.
- **Dashboard thời gian thực**:
  - Hero Card với **5 trạng thái thực tế** (*Protected, Attention Required, Threat Detected, Protection Disabled, Service Unavailable*).
  - 4 thẻ thao tác nhanh (*Quét nhanh, Quét toàn bộ, Quét tùy chỉnh, Cập nhật CSDL*).
  - Thống kê bảo mật lọc theo thời gian (*Hôm nay, 7 ngày qua, 30 ngày qua, Tất cả*) và biểu đồ Doughnut **LiveCharts2** phân loại 7 nhóm mối đe dọa (*Trojan, Ransomware, Spyware, Worm, Backdoor, Adware, Khác*).
- **Bộ quét đa luồng & Phân tích đa tầng**:
  - Hỗ trợ **Quét nhanh / Quét toàn bộ / Quét tùy chỉnh** (kéo thả tệp/thư mục), tạm dừng/tiếp tục/hủy quét.
  - Tra cứu chữ ký **SHA-256** trong SQLite, phát hiện chuẩn **EICAR**, quy tắc **YARA-style**, phân tích **PE Header + Shannon Entropy + Suspicious Win32 Imports + Heuristic Scoring**.
- **Bảo vệ thời gian thực (Real-time Protection)**:
  - Giám sát thư mục trọng yếu bằng `FileSystemWatcher` + hàng đợi bất đồng bộ, bộ lọc ngoại lệ (*Folder / File / Extension*) và điều khiển từng mô-đun bảo vệ.
- **Khu cách ly mã hóa AES-256-GCM (Quarantine Vault)**:
  - Mã hóa tệp nghi ngờ thành định dạng `.kqv` (AES-256-GCM + nonce 96-bit + authentication tag 128-bit), hỗ trợ **Khôi phục**, **Lưu nơi khác** và **Xóa vĩnh viễn** ghi đè an toàn.
- **Cập nhật chữ ký xác thực Ed25519 & Đồng bộ**:
  - Xác thực gói chữ ký bằng chữ ký số **Ed25519**, ghi giao dịch nguyên tử (SQLite transaction), gửi Device Heartbeat tới Backend REST API kèm hàng đợi đồng bộ ngoại tuyến.
- **Tài khoản người dùng cục bộ**:
  - Đăng ký tài khoản mới, đăng nhập bằng Tên đăng nhập hoặc Email, đo độ mạnh mật khẩu trực tiếp, đổi mật khẩu và lưu băm bằng **PBKDF2-SHA256 (120.000 vòng + muối 16 byte)**.

---

## Tải và chạy nhanh (File thực thi Windows `.exe`)

Không cần cài đặt .NET SDK hay Visual Studio:

1. Mở mục **[Releases](../../releases)** trên GitHub.
2. Tải về **`KryvnixAntivirus.exe`** (bản chạy trực tiếp một tệp duy nhất) hoặc **`KryvnixAntivirus-win-x64.zip`**.
3. Giải nén (nếu tải file `.zip`) và nhấp đúp **`KryvnixAntivirus.exe`** để chạy ngay trên Windows 10/11 (x64).

> **Lưu ý**: Ứng dụng tự tạo cơ sở dữ liệu SQLite cục bộ tại `%LocalAppData%\KryvnixAntivirus\kryvnix.db` và kho cách ly tại `%LocalAppData%\KryvnixAntivirus\Quarantine\`.

---

## Build từ mã nguồn (Dành cho nhà phát triển)

### Yêu cầu
- Windows 10/11 x64
- [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0)

### Các lệnh build, kiểm thử và đóng gói `.exe`

```powershell
# 1. Khôi phục gói NuGet và biên dịch
dotnet restore KryvnixAntivirus.slnx
dotnet build KryvnixAntivirus.slnx -c Release

# 2. Chạy toàn bộ unit test (11/11 tests)
dotnet test desktop/KryvnixAntivirus.Tests/KryvnixAntivirus.Tests.csproj -c Release

# 3. Chạy trực tiếp ứng dụng
dotnet run --project desktop/KryvnixAntivirus.Desktop/KryvnixAntivirus.Desktop.csproj -c Release

# 4. Đóng gói file thực thi độc lập (.exe self-contained)
dotnet publish desktop/KryvnixAntivirus.Desktop/KryvnixAntivirus.Desktop.csproj `
  -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
  -p:EnableCompressionInSingleFile=true -o publish/win-x64
```

---

## Cấu trúc dự án

```text
├── desktop/
│   ├── KryvnixAntivirus.Desktop/   # Ứng dụng WPF (.NET 10, MVVM, LiveCharts2, SQLite, AES-256-GCM)
│   └── KryvnixAntivirus.Tests/     # Bộ kiểm thử đơn vị xUnit (11 tests)
├── engine/                         # Nền tảng C++20 CMake + vcpkg & giao thức Named Pipe IPC
├── database/
│   ├── postgres/                   # Migration SQL PostgreSQL 16 (Backend)
│   └── sqlite/                     # Schema SQLite 3 (Endpoint cục bộ)
├── docs/                           # Tài liệu kiến trúc, ERD và ảnh minh họa
├── .github/workflows/release.yml   # GitHub Actions CI/CD tự động build, test & phát hành .exe
├── docker-compose.yml              # PostgreSQL 16 + Adminer
└── KryvnixAntivirus.slnx           # Solution .NET 10
```

Xem chi tiết kiến trúc hệ thống, sơ đồ ERD và lộ trình 10 phase tại [docs/Architecture-and-Roadmap.md](docs/Architecture-and-Roadmap.md).
