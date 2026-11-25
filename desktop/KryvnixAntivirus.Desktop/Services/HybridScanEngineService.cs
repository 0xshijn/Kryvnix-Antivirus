using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using KryvnixAntivirus.Desktop.Data;
using KryvnixAntivirus.Desktop.Models;

namespace KryvnixAntivirus.Desktop.Services;

public interface IScanEngineService
{
    bool IsScanning { get; }
    bool IsPaused { get; }
    event EventHandler<ScanProgressInfo>? ProgressChanged;
    event EventHandler<DetectionItem>? ThreatDetected;
    event EventHandler<ScanSummary>? ScanCompleted;

    Task<ScanSummary> StartScanAsync(ScanMode mode, IReadOnlyList<string>? customTargets = null, CancellationToken ct = default);
    void PauseScan();
    void ResumeScan();
    void CancelScan();
    bool IsExcluded(string filePath, IReadOnlyList<ExclusionItem> exclusions);
}

public sealed class HybridScanEngineService : IScanEngineService
{
    private readonly ILocalDatabaseService _db;
    private readonly ILocalThreatAnalyzer _analyzer;
    private readonly IEngineIpcClient _ipcClient;

    private CancellationTokenSource? _activeCts;
    private volatile bool _isPaused;
    private volatile bool _isScanning;
    private TaskCompletionSource<bool> _pauseTcs = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public bool IsScanning => _isScanning;
    public bool IsPaused => _isPaused;

    public event EventHandler<ScanProgressInfo>? ProgressChanged;
    public event EventHandler<DetectionItem>? ThreatDetected;
    public event EventHandler<ScanSummary>? ScanCompleted;

    public HybridScanEngineService(
        ILocalDatabaseService db,
        ILocalThreatAnalyzer analyzer,
        IEngineIpcClient ipcClient)
    {
        _db = db;
        _analyzer = analyzer;
        _ipcClient = ipcClient;
        _pauseTcs.TrySetResult(true);
    }

    public void PauseScan()
    {
        if (!_isScanning || _isPaused) return;
        _isPaused = true;
        _pauseTcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
    }

    public void ResumeScan()
    {
        if (!_isPaused) return;
        _isPaused = false;
        _pauseTcs.TrySetResult(true);
    }

    public void CancelScan()
    {
        ResumeScan();
        _activeCts?.Cancel();
    }

    public bool IsExcluded(string filePath, IReadOnlyList<ExclusionItem> exclusions)
    {
        foreach (var ex in exclusions)
        {
            if (string.IsNullOrWhiteSpace(ex.Value)) continue;
            switch (ex.ExclusionType.ToLowerInvariant())
            {
                case "folder":
                    if (filePath.StartsWith(ex.Value, StringComparison.OrdinalIgnoreCase)) return true;
                    break;
                case "file":
                    if (string.Equals(filePath, ex.Value, StringComparison.OrdinalIgnoreCase)) return true;
                    break;
                case "extension":
                    var normalizedExt = ex.Value.StartsWith('.') ? ex.Value : "." + ex.Value;
                    if (filePath.EndsWith(normalizedExt, StringComparison.OrdinalIgnoreCase)) return true;
                    break;
            }
        }
        return false;
    }

    public async Task<ScanSummary> StartScanAsync(ScanMode mode, IReadOnlyList<string>? customTargets = null, CancellationToken ct = default)
    {
        if (_isScanning)
        {
            throw new InvalidOperationException("Một phiên quét khác đang chạy.");
        }

        _isScanning = true;
        _isPaused = false;
        _pauseTcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pauseTcs.TrySetResult(true);

        _activeCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var token = _activeCts.Token;

        var sessionId = Guid.NewGuid().ToString("N");
        var startedAt = DateTime.Now;
        var sw = Stopwatch.StartNew();
        var settings = await _db.LoadSettingsAsync(token);
        var exclusions = await _db.GetExclusionsAsync(token);

        var targets = ResolveTargets(mode, customTargets);
        var targetLabel = targets.Count == 1 ? targets[0] : $"{targets.Count} vị trí ({mode})";

        // Attempt optional handshake with native C++ pipe if enabled
        if (settings.UseNativeServiceWhenAvailable)
        {
            _ = await _ipcClient.CheckStatusAsync(settings.NamedPipeName, settings.SimulateServiceUnavailable, token);
        }

        var detections = new ConcurrentBag<DetectionItem>();
        int filesScanned = 0;
        string status = "Completed";

        try
        {
            ProgressChanged?.Invoke(this, new ScanProgressInfo
            {
                Mode = mode,
                CurrentFilePath = "Đang lập danh sách tệp cần kiểm tra...",
                IsRunning = true,
                IsIndeterminate = true
            });

            var fileList = await Task.Run(() => EnumerateFilesSafe(targets, mode, exclusions, token), token);
            int totalFiles = Math.Max(1, fileList.Count);
            long maxBytes = Math.Max(1, settings.MaxFileSizeMb) * 1024L * 1024L;
            var parallelOptions = new ParallelOptions
            {
                MaxDegreeOfParallelism = Math.Clamp(settings.ScanThreadCount, 1, Math.Max(2, Environment.ProcessorCount)),
                CancellationToken = token
            };

            long lastReportTicks = 0;

            await Parallel.ForEachAsync(fileList, parallelOptions, async (filePath, innerCt) =>
            {
                if (_isPaused)
                {
                    await _pauseTcs.Task.WaitAsync(innerCt);
                }

                innerCt.ThrowIfCancellationRequested();

                var detection = await _analyzer.AnalyzeFileAsync(filePath, settings.HeuristicThreshold, maxBytes, innerCt);
                if (detection is not null)
                {
                    detection.ScanSessionId = sessionId;
                    detections.Add(detection);
                    await _db.RecordDetectionAsync(detection, innerCt);
                    ThreatDetected?.Invoke(this, detection);
                }

                int current = Interlocked.Increment(ref filesScanned);
                long nowTicks = sw.ElapsedMilliseconds;
                long prev = Interlocked.Read(ref lastReportTicks);
                if (nowTicks - prev >= 65 || current == totalFiles)
                {
                    if (Interlocked.CompareExchange(ref lastReportTicks, nowTicks, prev) == prev || current == totalFiles)
                    {
                        var elapsedSec = Math.Max(0.05, sw.Elapsed.TotalSeconds);
                        ProgressChanged?.Invoke(this, new ScanProgressInfo
                        {
                            Mode = mode,
                            CurrentFilePath = filePath,
                            FilesScanned = current,
                            TotalEstimatedFiles = fileList.Count,
                            ProgressPercent = Math.Min(100.0, current * 100.0 / totalFiles),
                            ThreatsFound = detections.Count,
                            FilesPerSecond = Math.Round(current / elapsedSec, 1),
                            Elapsed = sw.Elapsed,
                            IsPaused = _isPaused,
                            IsRunning = true,
                            IsIndeterminate = false
                        });
                    }
                }
            });
        }
        catch (OperationCanceledException)
        {
            status = "Cancelled";
        }
        finally
        {
            sw.Stop();
            _isScanning = false;
            _isPaused = false;
            _activeCts?.Dispose();
            _activeCts = null;
        }

        var summary = new ScanSummary
        {
            SessionId = sessionId,
            Mode = mode,
            TargetPath = targetLabel,
            FilesScanned = filesScanned,
            ThreatsFound = detections.Count,
            Duration = sw.Elapsed,
            Status = status,
            StartedAt = startedAt,
            CompletedAt = DateTime.Now,
            Detections = detections.OrderByDescending(d => d.Severity).ToList()
        };

        await _db.RecordScanSessionAsync(summary);

        var modeTitle = mode switch
        {
            ScanMode.Quick => "Quét nhanh",
            ScanMode.Full => "Quét toàn bộ",
            ScanMode.Custom => "Quét tùy chỉnh",
            _ => "Quét thời gian thực"
        };

        var eventDesc = summary.ThreatsFound > 0
            ? $"Đã quét {summary.FilesScanned:N0} tệp, phát hiện {summary.ThreatsFound} mối đe dọa"
            : $"Đã quét {summary.FilesScanned:N0} tệp, không phát hiện mối đe dọa";

        await _db.AddActivityEventAsync(new Models.ActivityEvent
        {
            EventType = summary.ThreatsFound > 0 ? ActivityEventType.MalwareDetected : ActivityEventType.ScanCompleted,
            Title = status == "Cancelled" ? $"{modeTitle} đã dừng" : $"{modeTitle} hoàn tất",
            Description = eventDesc,
            Severity = summary.ThreatsFound > 0 ? ThreatSeverity.High : ThreatSeverity.Low,
            IsRead = false,
            CreatedAt = DateTime.Now
        });

        ProgressChanged?.Invoke(this, new ScanProgressInfo
        {
            Mode = mode,
            CurrentFilePath = status == "Cancelled" ? "Phiên quét đã bị hủy." : "Quét hoàn tất.",
            FilesScanned = filesScanned,
            TotalEstimatedFiles = filesScanned,
            ProgressPercent = status == "Cancelled" ? 0 : 100,
            ThreatsFound = detections.Count,
            Elapsed = sw.Elapsed,
            IsRunning = false
        });

        ScanCompleted?.Invoke(this, summary);
        return summary;
    }

    private static List<string> ResolveTargets(ScanMode mode, IReadOnlyList<string>? customTargets)
    {
        if (customTargets is { Count: > 0 })
        {
            return customTargets.Where(t => Directory.Exists(t) || File.Exists(t)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        }

        var list = new List<string>();
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var downloads = Path.Combine(userProfile, "Downloads");
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        var startup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
        var temp = Path.GetTempPath();

        if (mode == ScanMode.Quick)
        {
            foreach (var path in new[] { downloads, desktop, startup, temp })
            {
                if (Directory.Exists(path)) list.Add(path);
            }
        }
        else if (mode == ScanMode.Full)
        {
            var docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            foreach (var path in new[] { downloads, desktop, docs, startup, temp, appData })
            {
                if (Directory.Exists(path)) list.Add(path);
            }
        }

        if (list.Count == 0 && Directory.Exists(userProfile))
        {
            list.Add(userProfile);
        }

        return list;
    }

    private List<string> EnumerateFilesSafe(IReadOnlyList<string> targets, ScanMode mode, IReadOnlyList<ExclusionItem> exclusions, CancellationToken ct)
    {
        var files = new List<string>(2048);
        int cap = mode switch
        {
            ScanMode.Quick => 2500,
            ScanMode.Full => 15000,
            _ => 50000
        };

        var vaultDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "KryvnixAntivirus", "Quarantine");

        foreach (var target in targets)
        {
            ct.ThrowIfCancellationRequested();

            if (File.Exists(target))
            {
                if (!IsExcluded(target, exclusions)) files.Add(target);
                continue;
            }

            if (!Directory.Exists(target)) continue;

            var stack = new Stack<(string Dir, int Depth)>();
            stack.Push((target, 0));
            int maxDepth = mode == ScanMode.Quick ? 3 : mode == ScanMode.Full ? 5 : 10;

            while (stack.Count > 0 && files.Count < cap)
            {
                ct.ThrowIfCancellationRequested();
                var (dir, depth) = stack.Pop();

                if (dir.StartsWith(vaultDir, StringComparison.OrdinalIgnoreCase)) continue;
                if (IsExcluded(dir, exclusions)) continue;

                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir))
                    {
                        if (files.Count >= cap) break;
                        if (!IsExcluded(file, exclusions))
                        {
                            files.Add(file);
                        }
                    }
                }
                catch
                {
                    // Skip protected/inaccessible folders cleanly
                }

                if (depth < maxDepth)
                {
                    try
                    {
                        foreach (var sub in Directory.EnumerateDirectories(dir))
                        {
                            var name = Path.GetFileName(sub);
                            if (name.Equals("node_modules", StringComparison.OrdinalIgnoreCase) ||
                                name.Equals(".git", StringComparison.OrdinalIgnoreCase) ||
                                name.Equals("WinSxS", StringComparison.OrdinalIgnoreCase))
                            {
                                continue;
                            }

                            stack.Push((sub, depth + 1));
                        }
                    }
                    catch
                    {
                        // Ignore permission denied
                    }
                }
            }
        }

        return files;
    }
}
