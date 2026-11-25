using System.Diagnostics;
using System.IO;
using KryvnixAntivirus.Desktop.Models;
using Microsoft.Win32;

namespace KryvnixAntivirus.Desktop.Services;

public interface ISystemSecurityGuardService
{
    Task<List<ProcessMonitorItem>> GetMonitoredProcessesAsync(CancellationToken ct = default);
    Task<bool> TerminateProcessAsync(int pid);
    Task<List<StartupGuardItem>> GetStartupEntriesAsync(CancellationToken ct = default);
    bool RemoveHkcuStartupEntry(string entryName);
}

public sealed class SystemSecurityGuardService : ISystemSecurityGuardService
{
    private readonly IAuthenticodeVerifier _authenticode;

    private static readonly string[] SuspiciousPathFragments =
    [
        @"\appdata\local\temp\",
        @"\windows\temp\",
        @"\users\public\",
        @"\downloads\"
    ];

    private static readonly string[] SuspiciousStartupMarkers =
    [
        "powershell -enc",
        "powershell.exe -w hidden",
        "cmd.exe /c",
        "mshta ",
        "wscript ",
        "cscript ",
        "regsvr32 /s",
        @"\temp\"
    ];

    public SystemSecurityGuardService(IAuthenticodeVerifier authenticode)
    {
        _authenticode = authenticode;
    }

    public Task<List<ProcessMonitorItem>> GetMonitoredProcessesAsync(CancellationToken ct = default)
    {
        return Task.Run(() =>
        {
            var results = new List<ProcessMonitorItem>();
            var processes = Process.GetProcesses();

            foreach (var proc in processes)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    string path = string.Empty;
                    try
                    {
                        path = proc.MainModule?.FileName ?? string.Empty;
                    }
                    catch
                    {
                        // Protected system/elevated process
                    }

                    if (string.IsNullOrWhiteSpace(path)) continue;

                    var lowerPath = path.ToLowerInvariant();
                    bool inSuspiciousDir = SuspiciousPathFragments.Any(f => lowerPath.Contains(f));
                    bool isSigned = false;
                    string signer = "Không có chữ ký số";

                    // Verify Authenticode on non-System32 or suspicious-path executables
                    if (inSuspiciousDir || !lowerPath.StartsWith(@"c:\windows\system32\", StringComparison.OrdinalIgnoreCase))
                    {
                        var auth = _authenticode.VerifyFile(path);
                        isSigned = auth.IsValidSignature;
                        if (isSigned) signer = auth.SignerName;
                    }
                    else
                    {
                        isSigned = true;
                        signer = "Microsoft Windows (System32)";
                    }

                    bool suspicious = inSuspiciousDir && !isSigned;
                    string reason = suspicious
                        ? "Chạy không chữ ký số từ thư mục tạm / tải về"
                        : (isSigned ? "Đã xác thực chữ ký số" : "Chưa ký số (Thư mục thông thường)");

                    results.Add(new ProcessMonitorItem
                    {
                        Pid = proc.Id,
                        ProcessName = proc.ProcessName,
                        ExecutablePath = path,
                        MemoryMb = Math.Round(proc.WorkingSet64 / (1024.0 * 1024.0), 1),
                        IsSigned = isSigned,
                        SignerName = signer,
                        IsSuspicious = suspicious,
                        RiskReason = reason
                    });
                }
                catch
                {
                    // Process exited during enumeration
                }
                finally
                {
                    proc.Dispose();
                }
            }

            return results
                .OrderByDescending(p => p.IsSuspicious)
                .ThenByDescending(p => p.MemoryMb)
                .Take(45)
                .ToList();
        }, ct);
    }

    public Task<bool> TerminateProcessAsync(int pid)
    {
        return Task.Run(() =>
        {
            try
            {
                using var proc = Process.GetProcessById(pid);
                if (proc.Id == Environment.ProcessId) return false;
                proc.Kill(entireProcessTree: true);
                return true;
            }
            catch
            {
                return false;
            }
        });
    }

    public Task<List<StartupGuardItem>> GetStartupEntriesAsync(CancellationToken ct = default)
    {
        return Task.Run(() =>
        {
            var items = new List<StartupGuardItem>();
            ReadRegistryRunKey(Registry.CurrentUser, "HKCU", @"Software\Microsoft\Windows\CurrentVersion\Run", canRemove: true, items);
            ReadRegistryRunKey(Registry.CurrentUser, "HKCU", @"Software\Microsoft\Windows\CurrentVersion\RunOnce", canRemove: true, items);
            ReadRegistryRunKey(Registry.LocalMachine, "HKLM", @"Software\Microsoft\Windows\CurrentVersion\Run", canRemove: false, items);

            return items.OrderByDescending(i => i.IsSuspicious).ThenBy(i => i.Name).ToList();
        }, ct);
    }

    public bool RemoveHkcuStartupEntry(string entryName)
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", writable: true);
            if (key?.GetValue(entryName) is not null)
            {
                key.DeleteValue(entryName, throwOnMissingValue: false);
                return true;
            }

            using var keyOnce = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\RunOnce", writable: true);
            if (keyOnce?.GetValue(entryName) is not null)
            {
                keyOnce.DeleteValue(entryName, throwOnMissingValue: false);
                return true;
            }

            return false;
        }
        catch
        {
            return false;
        }
    }

    private static void ReadRegistryRunKey(RegistryKey root, string hiveLabel, string subPath, bool canRemove, List<StartupGuardItem> items)
    {
        try
        {
            using var key = root.OpenSubKey(subPath, writable: false);
            if (key is null) return;

            foreach (var name in key.GetValueNames())
            {
                var command = key.GetValue(name)?.ToString() ?? string.Empty;
                var lowerCmd = command.ToLowerInvariant();
                var matchedMarker = SuspiciousStartupMarkers.FirstOrDefault(m => lowerCmd.Contains(m));
                bool suspicious = matchedMarker is not null;

                items.Add(new StartupGuardItem
                {
                    Name = name,
                    Command = command,
                    Hive = hiveLabel,
                    RegistryPath = $@"{hiveLabel}\{subPath}",
                    IsSuspicious = suspicious,
                    RiskReason = suspicious ? $"Lệnh khởi động nghi vấn ({matchedMarker})" : "Khởi động hợp lệ",
                    CanRemove = canRemove
                });
            }
        }
        catch
        {
            // Ignore registry permission restrictions
        }
    }
}
