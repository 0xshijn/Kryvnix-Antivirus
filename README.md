# Kryvnix Antivirus

Ứng dụng bảo mật điểm cuối (Windows Endpoint Antivirus) với giao diện desktop **C# / .NET 10 / WPF / MVVM** theo phong cách Fluent Dark và nền tảng kiến trúc đa tầng (SQLite cục bộ, AES-256-GCM Quarantine Vault, Windows Named Pipe IPC, Ed25519 Signature Verification, PostgreSQL + Docker Compose, C++20 CMake/vcpkg Engine).

## Cấu trúc thư mục

- `desktop/KryvnixAntivirus.Desktop` — Ứng dụng Desktop WPF (.NET 10, CommunityToolkit.Mvvm, LiveCharts2, SQLite, DI, System Tray)
- `desktop/KryvnixAntivirus.Tests` — Bộ kiểm thử đơn vị xUnit (EICAR, False Positive, PE Heuristic, AES-256-GCM Quarantine, Ed25519, Dashboard Analytics)
- `engine/` — Khung C++20 CMake + vcpkg & giao thức Named Pipe IPC (`\\.\pipe\KryvnixAntivirusPipe`)
- `database/` — Migration SQL cho PostgreSQL 16 (Backend) và SQLite 3 (Endpoint cục bộ)
- `docker-compose.yml` — Môi trường PostgreSQL + Adminer cho Backend

## Build & Chạy ứng dụng (.NET 10)

```powershell
$env:PATH = "$env:USERPROFILE\.dotnet;$env:PATH"
dotnet test desktop/KryvnixAntivirus.Tests/KryvnixAntivirus.Tests.csproj
dotnet run --project desktop/KryvnixAntivirus.Desktop/KryvnixAntivirus.Desktop.csproj
```
