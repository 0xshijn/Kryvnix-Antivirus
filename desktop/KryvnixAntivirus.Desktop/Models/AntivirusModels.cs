namespace KryvnixAntivirus.Desktop.Models;

public enum ProtectionState
{
    Protected,
    AttentionRequired,
    ThreatDetected,
    ProtectionDisabled,
    ServiceUnavailable
}

public enum NavigationPage
{
    Dashboard,
    VirusScan,
    RealtimeProtection,
    Quarantine,
    ActivityHistory,
    Updates,
    Settings
}

public enum ScanMode
{
    Quick,
    Full,
    Custom,
    Realtime
}

public enum TimeRangeFilter
{
    Today,
    Last7Days,
    Last30Days,
    AllTime
}

public enum ThreatCategory
{
    Trojan,
    Ransomware,
    Spyware,
    Worm,
    Backdoor,
    Adware,
    Other
}

public enum ThreatSeverity
{
    Low,
    Medium,
    High,
    Critical
}

public enum ActivityEventType
{
    ScanCompleted,
    MalwareDetected,
    FileQuarantined,
    FileRestored,
    FileDeleted,
    DatabaseUpdated,
    ProtectionChanged,
    SystemInfo
}

public sealed class ThreatCategoryStat
{
    public ThreatCategory Category { get; set; }
    public string DisplayName { get; set; } = string.Empty;
    public int Count { get; set; }
    public double Percentage { get; set; }
    public string ColorHex { get; set; } = "#22C55E";
    public string FormattedStat => $"{Percentage:0.0}% ({Count})";
}

public sealed class DashboardStats
{
    public long TotalFilesScanned { get; set; }
    public int ThreatsDetected { get; set; }
    public int ActiveThreatsCount { get; set; }
    public int QuarantinedFilesCount { get; set; }
    public long DatabaseSignaturesCount { get; set; }
    public string DatabaseVersion { get; set; } = "v2025.01.15";
    public DateTime? LastScanTime { get; set; }
    public List<ThreatCategoryStat> ThreatBreakdown { get; set; } = [];
}

public sealed class ActivityEvent
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public ActivityEventType EventType { get; set; }
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public ThreatSeverity Severity { get; set; } = ThreatSeverity.Low;
    public bool IsRead { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.Now;
}

public sealed class DetectionItem
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string? ScanSessionId { get; set; }
    public string FileName { get; set; } = string.Empty;
    public string FilePath { get; set; } = string.Empty;
    public string Sha256 { get; set; } = string.Empty;
    public string ThreatName { get; set; } = string.Empty;
    public ThreatCategory Category { get; set; } = ThreatCategory.Other;
    public ThreatSeverity Severity { get; set; } = ThreatSeverity.High;
    public string DetectionMethod { get; set; } = "Signature";
    public int HeuristicScore { get; set; }
    public double Entropy { get; set; }
    public long FileSize { get; set; }
    public string ActionTaken { get; set; } = "Detected";
    public DateTime DetectedAt { get; set; } = DateTime.Now;
}

public sealed class ScanProgressInfo
{
    public ScanMode Mode { get; set; }
    public string CurrentFilePath { get; set; } = string.Empty;
    public int FilesScanned { get; set; }
    public int TotalEstimatedFiles { get; set; }
    public double ProgressPercent { get; set; }
    public int ThreatsFound { get; set; }
    public double FilesPerSecond { get; set; }
    public TimeSpan Elapsed { get; set; }
    public bool IsPaused { get; set; }
    public bool IsRunning { get; set; }
    public bool IsIndeterminate { get; set; }
}

public sealed class ScanSummary
{
    public string SessionId { get; set; } = Guid.NewGuid().ToString("N");
    public ScanMode Mode { get; set; }
    public string TargetPath { get; set; } = string.Empty;
    public int FilesScanned { get; set; }
    public int ThreatsFound { get; set; }
    public TimeSpan Duration { get; set; }
    public string Status { get; set; } = "Completed";
    public DateTime StartedAt { get; set; } = DateTime.Now;
    public DateTime CompletedAt { get; set; } = DateTime.Now;
    public List<DetectionItem> Detections { get; set; } = [];
}

public sealed class QuarantineItem
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string OriginalName { get; set; } = string.Empty;
    public string OriginalPath { get; set; } = string.Empty;
    public string VaultFilePath { get; set; } = string.Empty;
    public string ThreatName { get; set; } = string.Empty;
    public ThreatCategory Category { get; set; }
    public ThreatSeverity Severity { get; set; }
    public string Sha256 { get; set; } = string.Empty;
    public long FileSize { get; set; }
    public string NonceBase64 { get; set; } = string.Empty;
    public string TagBase64 { get; set; } = string.Empty;
    public string Status { get; set; } = "Quarantined";
    public DateTime QuarantinedAt { get; set; } = DateTime.Now;
}

public sealed class ExclusionItem
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string ExclusionType { get; set; } = "Folder";
    public string Value { get; set; } = string.Empty;
    public string Reason { get; set; } = string.Empty;
    public DateTime AddedAt { get; set; } = DateTime.Now;
}

public sealed class UpdateHistoryItem
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Version { get; set; } = "v2025.01.15";
    public int SignaturesAdded { get; set; }
    public long TotalSignatures { get; set; }
    public bool VerifiedEd25519 { get; set; } = true;
    public string Changelog { get; set; } = string.Empty;
    public DateTime InstalledAt { get; set; } = DateTime.Now;
}

public sealed class RealtimeProtectionState
{
    public bool IsMasterEnabled { get; set; } = true;
    public bool FileMonitorEnabled { get; set; } = true;
    public bool ProcessMonitorEnabled { get; set; } = true;
    public bool NetworkShieldEnabled { get; set; } = true;
    public bool BehaviorMonitorEnabled { get; set; } = true;
    public int HeuristicSensitivity { get; set; } = 2; // 1 = Low, 2 = Balanced, 3 = High
    public bool AutoQuarantineRealtime { get; set; } = true;
}

public sealed class AppSettings
{
    public bool StartWithWindows { get; set; } = true;
    public bool MinimizeToTrayOnClose { get; set; } = true;
    public bool ShowDesktopNotifications { get; set; } = true;
    public int ScanThreadCount { get; set; } = Math.Max(2, Environment.ProcessorCount / 2);
    public int MaxFileSizeMb { get; set; } = 100;
    public bool ScanArchives { get; set; } = true;
    public int HeuristicThreshold { get; set; } = 65;
    public string DefaultThreatAction { get; set; } = "Ask";
    public bool UseNativeServiceWhenAvailable { get; set; } = true;
    public string NamedPipeName { get; set; } = "KryvnixAntivirusPipe";
    public string BackendApiBaseUrl { get; set; } = "http://localhost:8080/api/v1";
    public int AutoUpdateIntervalHours { get; set; } = 4;
    public string DatabaseVersion { get; set; } = "v2025.01.15";
    public long BaseSignatureCatalogCount { get; set; } = 1482640;
    public string DeviceId { get; set; } = $"KRV-{Environment.MachineName.ToUpperInvariant()}";
    public bool HasPendingUpdate { get; set; } = true;
    public bool SimulateServiceUnavailable { get; set; }
}

public sealed class EngineStatusSnapshot
{
    public bool IsNativeServiceConnected { get; set; }
    public bool IsEngineOperational { get; set; } = true;
    public string EngineVersion { get; set; } = "1.0.0";
    public string DatabaseVersion { get; set; } = "v2025.01.15";
    public string EngineModeLabel => IsNativeServiceConnected
        ? "C++ Native Service (Named Pipe)"
        : (IsEngineOperational ? "Local Hybrid Engine (.NET)" : "Service Unavailable");
    public DateTime CheckedAt { get; set; } = DateTime.Now;
}

public sealed class MalwareSignatureRecord
{
    public string Sha256 { get; set; } = string.Empty;
    public string ThreatName { get; set; } = string.Empty;
    public ThreatCategory Category { get; set; }
    public ThreatSeverity Severity { get; set; }
    public string PackageVersion { get; set; } = "v2025.01.15";
}

public sealed class SignatureUpdateResult
{
    public bool Success { get; set; }
    public bool AlreadyUpToDate { get; set; }
    public string NewVersion { get; set; } = string.Empty;
    public int SignaturesAdded { get; set; }
    public long TotalSignatures { get; set; }
    public bool Ed25519Verified { get; set; }
    public string Message { get; set; } = string.Empty;
}

public sealed class UserAccount
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string FullName { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public string Role { get; set; } = "Standard";
    public DateTime CreatedAt { get; set; } = DateTime.Now;
    public DateTime? LastLoginAt { get; set; }

    public string Initials
    {
        get
        {
            var parts = FullName.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 2)
            {
                return $"{char.ToUpperInvariant(parts[0][0])}{char.ToUpperInvariant(parts[^1][0])}";
            }
            if (!string.IsNullOrWhiteSpace(FullName))
            {
                return FullName[..Math.Min(2, FullName.Length)].ToUpperInvariant();
            }
            return string.IsNullOrWhiteSpace(Username) ? "ND" : Username[..Math.Min(2, Username.Length)].ToUpperInvariant();
        }
    }
}

public sealed class AuthResult
{
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
    public UserAccount? User { get; set; }

    public static AuthResult Ok(UserAccount user, string message) => new() { Success = true, User = user, Message = message };
    public static AuthResult Fail(string message) => new() { Success = false, Message = message };
}

public static class ThreatCategoryMetadata
{
    public static string GetDisplayName(ThreatCategory category) => category switch
    {
        ThreatCategory.Trojan => "Trojan",
        ThreatCategory.Ransomware => "Ransomware",
        ThreatCategory.Spyware => "Spyware",
        ThreatCategory.Worm => "Worm",
        ThreatCategory.Backdoor => "Backdoor",
        ThreatCategory.Adware => "Adware",
        _ => "Khác"
    };

    public static string GetColorHex(ThreatCategory category) => category switch
    {
        ThreatCategory.Trojan => "#EF4444",
        ThreatCategory.Ransomware => "#F97316",
        ThreatCategory.Spyware => "#FACC15",
        ThreatCategory.Worm => "#22C55E",
        ThreatCategory.Backdoor => "#3B82F6",
        ThreatCategory.Adware => "#06B6D4",
        _ => "#8B5CF6"
    };
}
