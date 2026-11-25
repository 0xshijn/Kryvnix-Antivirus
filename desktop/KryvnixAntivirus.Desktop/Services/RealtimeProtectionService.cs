using System.Collections.Concurrent;
using System.IO;
using System.Threading.Channels;
using KryvnixAntivirus.Desktop.Data;
using KryvnixAntivirus.Desktop.Models;

namespace KryvnixAntivirus.Desktop.Services;

public interface IRealtimeProtectionService : IDisposable
{
    RealtimeProtectionState CurrentState { get; }
    IReadOnlyList<string> MonitoredPaths { get; }
    event EventHandler<RealtimeProtectionState>? StateChanged;
    event EventHandler<DetectionItem>? ThreatIntercepted;
    event EventHandler<string>? MonitorActivityLogged;

    Task InitializeAsync(CancellationToken ct = default);
    Task UpdateStateAsync(RealtimeProtectionState newState, CancellationToken ct = default);
    Task TriggerManualFileCheckAsync(string filePath, CancellationToken ct = default);
}

public sealed class RealtimeProtectionService : IRealtimeProtectionService
{
    private readonly ILocalDatabaseService _db;
    private readonly ILocalThreatAnalyzer _analyzer;
    private readonly IQuarantineService _quarantine;
    private readonly IScanEngineService _scanner;

    private readonly List<FileSystemWatcher> _watchers = [];
    private readonly Channel<string> _eventQueue = Channel.CreateBounded<string>(new BoundedChannelOptions(512)
    {
        FullMode = BoundedChannelFullMode.DropOldest
    });
    private readonly ConcurrentDictionary<string, DateTime> _recentFiles = new(StringComparer.OrdinalIgnoreCase);
    private CancellationTokenSource? _workerCts;
    private Task? _workerTask;

    public RealtimeProtectionState CurrentState { get; private set; } = new();
    public IReadOnlyList<string> MonitoredPaths { get; private set; } = [];

    public event EventHandler<RealtimeProtectionState>? StateChanged;
    public event EventHandler<DetectionItem>? ThreatIntercepted;
    public event EventHandler<string>? MonitorActivityLogged;

    public RealtimeProtectionService(
        ILocalDatabaseService db,
        ILocalThreatAnalyzer analyzer,
        IQuarantineService quarantine,
        IScanEngineService scanner)
    {
        _db = db;
        _analyzer = analyzer;
        _quarantine = quarantine;
        _scanner = scanner;
    }

    public async Task InitializeAsync(CancellationToken ct = default)
    {
        CurrentState = await _db.LoadRealtimeStateAsync(ct);

        var paths = new List<string>();
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var downloads = Path.Combine(userProfile, "Downloads");
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);

        if (Directory.Exists(downloads)) paths.Add(downloads);
        if (Directory.Exists(desktop)) paths.Add(desktop);
        MonitoredPaths = paths;

        _workerCts = new CancellationTokenSource();
        _workerTask = Task.Run(() => ProcessQueueAsync(_workerCts.Token));

        ApplyWatchers();
        StateChanged?.Invoke(this, CurrentState);
    }

    public async Task UpdateStateAsync(RealtimeProtectionState newState, CancellationToken ct = default)
    {
        bool masterChanged = CurrentState.IsMasterEnabled != newState.IsMasterEnabled;
        CurrentState = new RealtimeProtectionState
        {
            IsMasterEnabled = newState.IsMasterEnabled,
            FileMonitorEnabled = newState.FileMonitorEnabled,
            ProcessMonitorEnabled = newState.ProcessMonitorEnabled,
            NetworkShieldEnabled = newState.NetworkShieldEnabled,
            BehaviorMonitorEnabled = newState.BehaviorMonitorEnabled,
            HeuristicSensitivity = newState.HeuristicSensitivity,
            AutoQuarantineRealtime = newState.AutoQuarantineRealtime
        };

        await _db.SaveRealtimeStateAsync(CurrentState, ct);
        ApplyWatchers();

        if (masterChanged)
        {
            await _db.AddActivityEventAsync(new ActivityEvent
            {
                EventType = ActivityEventType.ProtectionChanged,
                Title = CurrentState.IsMasterEnabled ? "Đã bật Bảo vệ thời gian thực" : "Đã tắt Bảo vệ thời gian thực",
                Description = CurrentState.IsMasterEnabled
                    ? "Tất cả cảm biến giám sát tệp tin, tiến trình và hành vi đang bảo vệ hệ thống"
                    : "Cảnh báo: Thiết bị không được bảo vệ chủ động trước mối đe dọa mới",
                Severity = CurrentState.IsMasterEnabled ? ThreatSeverity.Low : ThreatSeverity.High,
                IsRead = false,
                CreatedAt = DateTime.Now
            }, ct);
        }

        StateChanged?.Invoke(this, CurrentState);
    }

    public Task TriggerManualFileCheckAsync(string filePath, CancellationToken ct = default)
    {
        _eventQueue.Writer.TryWrite(filePath);
        return Task.CompletedTask;
    }

    private void ApplyWatchers()
    {
        foreach (var w in _watchers)
        {
            w.EnableRaisingEvents = false;
            w.Dispose();
        }
        _watchers.Clear();

        if (!CurrentState.IsMasterEnabled || !CurrentState.FileMonitorEnabled)
        {
            MonitorActivityLogged?.Invoke(this, $"[{DateTime.Now:HH:mm:ss}] Giám sát tệp tin thời gian thực đã tạm dừng.");
            return;
        }

        foreach (var dir in MonitoredPaths)
        {
            try
            {
                var watcher = new FileSystemWatcher(dir)
                {
                    IncludeSubdirectories = false,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime,
                    EnableRaisingEvents = true
                };
                watcher.Created += OnFileEvent;
                watcher.Changed += OnFileEvent;
                watcher.Renamed += (_, e) => EnqueuePath(e.FullPath);
                _watchers.Add(watcher);
            }
            catch
            {
                // Skip unwatcheable folders cleanly
            }
        }

        MonitorActivityLogged?.Invoke(this, $"[{DateTime.Now:HH:mm:ss}] Đang giám sát {_watchers.Count} thư mục trọng yếu (Downloads, Desktop).");
    }

    private void OnFileEvent(object sender, FileSystemEventArgs e) => EnqueuePath(e.FullPath);

    private void EnqueuePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return;
        if (path.EndsWith(".kqv", StringComparison.OrdinalIgnoreCase) || path.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase)) return;

        var now = DateTime.UtcNow;
        if (_recentFiles.TryGetValue(path, out var prev) && (now - prev).TotalSeconds < 2)
        {
            return;
        }
        _recentFiles[path] = now;
        _eventQueue.Writer.TryWrite(path);
    }

    private async Task ProcessQueueAsync(CancellationToken ct)
    {
        await foreach (var path in _eventQueue.Reader.ReadAllAsync(ct))
        {
            if (!CurrentState.IsMasterEnabled || !CurrentState.FileMonitorEnabled) continue;

            try
            {
                await Task.Delay(180, ct); // Let writer flush file handle
                if (!File.Exists(path)) continue;

                var exclusions = await _db.GetExclusionsAsync(ct);
                if (_scanner.IsExcluded(path, exclusions)) continue;

                var settings = await _db.LoadSettingsAsync(ct);
                int threshold = CurrentState.HeuristicSensitivity switch
                {
                    3 => Math.Max(45, settings.HeuristicThreshold - 15),
                    1 => Math.Min(90, settings.HeuristicThreshold + 15),
                    _ => settings.HeuristicThreshold
                };

                MonitorActivityLogged?.Invoke(this, $"[{DateTime.Now:HH:mm:ss}] Đã kiểm tra tệp mới: {Path.GetFileName(path)}");

                var detection = await _analyzer.AnalyzeFileAsync(path, threshold, settings.MaxFileSizeMb * 1024L * 1024L, ct);
                if (detection is not null)
                {
                    await _db.RecordDetectionAsync(detection, ct);

                    if (CurrentState.AutoQuarantineRealtime)
                    {
                        await _quarantine.QuarantineFileAsync(detection, ct);
                        detection.ActionTaken = "Quarantined";
                    }
                    else
                    {
                        await _db.AddActivityEventAsync(new ActivityEvent
                        {
                            EventType = ActivityEventType.MalwareDetected,
                            Title = "Bảo vệ thời gian thực phát hiện mã độc",
                            Description = $"{detection.FileName} ({detection.ThreatName}) - Chờ xử lý",
                            Severity = detection.Severity,
                            IsRead = false,
                            CreatedAt = DateTime.Now
                        }, ct);
                    }

                    MonitorActivityLogged?.Invoke(this, $"[{DateTime.Now:HH:mm:ss}] CHẶN MỐI ĐE DỌA: {detection.FileName} -> {detection.ThreatName}");
                    ThreatIntercepted?.Invoke(this, detection);
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch
            {
                // Continue monitoring smoothly
            }
        }
    }

    public void Dispose()
    {
        _workerCts?.Cancel();
        foreach (var w in _watchers)
        {
            w.EnableRaisingEvents = false;
            w.Dispose();
        }
        _watchers.Clear();
        _workerCts?.Dispose();
    }
}
