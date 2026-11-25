using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using KryvnixAntivirus.Desktop.Data;
using KryvnixAntivirus.Desktop.Models;
using KryvnixAntivirus.Desktop.Services;
using Microsoft.Win32;
using WinForms = System.Windows.Forms;

namespace KryvnixAntivirus.Desktop.ViewModels;

public partial class ScanViewModel : ObservableObject
{
    private readonly IScanEngineService _scanner;
    private readonly IQuarantineService _quarantine;
    private readonly ILocalDatabaseService _db;
    private readonly IAppStateService _appState;
    private readonly IThreatIntelligenceService _threatIntel;

    [ObservableProperty] private ScanMode _selectedMode = ScanMode.Quick;
    [ObservableProperty] private bool _isScanning;
    [ObservableProperty] private bool _isPaused;
    [ObservableProperty] private bool _isIndeterminate;
    [ObservableProperty] private double _progressPercent;
    [ObservableProperty] private string _currentFilePath = "Sẵn sàng quét hệ thống.";
    [ObservableProperty] private int _filesScanned;
    [ObservableProperty] private int _totalEstimatedFiles;
    [ObservableProperty] private int _threatsFound;
    [ObservableProperty] private double _filesPerSecond;
    [ObservableProperty] private string _elapsedDisplay = "00:00";
    [ObservableProperty] private string _statusBanner = "Chọn chế độ quét bên dưới để bắt đầu kiểm tra hệ thống.";
    [ObservableProperty] private bool _hasCompletedSummary;

    public ObservableCollection<string> CustomTargets { get; } = [];
    public ObservableCollection<DetectionItem> DetectedThreats { get; } = [];

    public bool IsQuickSelected => SelectedMode == ScanMode.Quick;
    public bool IsFullSelected => SelectedMode == ScanMode.Full;
    public bool IsCustomSelected => SelectedMode == ScanMode.Custom;
    public string PauseButtonLabel => IsPaused ? "Tiếp tục" : "Tạm dừng";

    public ScanViewModel(
        IScanEngineService scanner,
        IQuarantineService quarantine,
        ILocalDatabaseService db,
        IAppStateService appState,
        IThreatIntelligenceService threatIntel)
    {
        _scanner = scanner;
        _quarantine = quarantine;
        _db = db;
        _appState = appState;
        _threatIntel = threatIntel;

        _scanner.ProgressChanged += (_, info) => Application.Current?.Dispatcher.Invoke(() =>
        {
            IsScanning = info.IsRunning;
            IsPaused = info.IsPaused;
            IsIndeterminate = info.IsIndeterminate;
            ProgressPercent = info.ProgressPercent;
            CurrentFilePath = info.CurrentFilePath;
            FilesScanned = info.FilesScanned;
            TotalEstimatedFiles = info.TotalEstimatedFiles;
            ThreatsFound = info.ThreatsFound;
            FilesPerSecond = info.FilesPerSecond;
            ElapsedDisplay = info.Elapsed.ToString(@"mm\:ss");
            OnPropertyChanged(nameof(PauseButtonLabel));
        });

        _scanner.ThreatDetected += (_, item) => Application.Current?.Dispatcher.Invoke(() =>
        {
            DetectedThreats.Insert(0, item);
        });
    }

    partial void OnSelectedModeChanged(ScanMode value)
    {
        OnPropertyChanged(nameof(IsQuickSelected));
        OnPropertyChanged(nameof(IsFullSelected));
        OnPropertyChanged(nameof(IsCustomSelected));
    }

    partial void OnIsPausedChanged(bool value) => OnPropertyChanged(nameof(PauseButtonLabel));

    public async Task TriggerModeFromExternalAsync(ScanMode mode)
    {
        SelectedMode = mode;
        if (mode == ScanMode.Custom)
        {
            StatusBanner = "Thêm thư mục/tệp hoặc kéo thả vào vùng bên dưới rồi nhấn Bắt đầu quét.";
            return;
        }

        if (!IsScanning)
        {
            await StartSelectedScanAsync();
        }
    }

    [RelayCommand]
    private void SelectMode(ScanMode mode) => SelectedMode = mode;

    [RelayCommand]
    private void BrowseFolder()
    {
        using var dialog = new WinForms.FolderBrowserDialog
        {
            Description = "Chọn thư mục cần quét mã độc",
            UseDescriptionForTitle = true
        };
        if (dialog.ShowDialog() == WinForms.DialogResult.OK && !string.IsNullOrWhiteSpace(dialog.SelectedPath))
        {
            AddTargetPath(dialog.SelectedPath);
            SelectedMode = ScanMode.Custom;
        }
    }

    [RelayCommand]
    private void BrowseFiles()
    {
        var dialog = new OpenFileDialog
        {
            Title = "Chọn tệp tin cần quét",
            Multiselect = true,
            Filter = "Tất cả tệp (*.*)|*.*"
        };
        if (dialog.ShowDialog() == true)
        {
            foreach (var f in dialog.FileNames)
            {
                AddTargetPath(f);
            }
            SelectedMode = ScanMode.Custom;
        }
    }

    public void AddTargetPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return;
        if (!CustomTargets.Contains(path, StringComparer.OrdinalIgnoreCase))
        {
            CustomTargets.Add(path);
        }
    }

    [RelayCommand]
    private void RemoveTarget(string path) => CustomTargets.Remove(path);

    [RelayCommand]
    private void ClearTargets() => CustomTargets.Clear();

    [RelayCommand]
    private async Task StartSelectedScanAsync()
    {
        if (IsScanning) return;

        if (SelectedMode == ScanMode.Custom && CustomTargets.Count == 0)
        {
            StatusBanner = "Vui lòng chọn ít nhất một tệp hoặc thư mục cho Quét tùy chỉnh.";
            return;
        }

        DetectedThreats.Clear();
        HasCompletedSummary = false;
        FilesScanned = 0;
        ThreatsFound = 0;
        ProgressPercent = 0;
        StatusBanner = SelectedMode switch
        {
            ScanMode.Quick => "Đang thực hiện Quét nhanh các khu vực trọng yếu...",
            ScanMode.Full => "Đang thực hiện Quét toàn bộ hệ thống...",
            _ => $"Đang quét {CustomTargets.Count} vị trí tùy chỉnh..."
        };

        try
        {
            var targets = SelectedMode == ScanMode.Custom ? CustomTargets.ToList() : null;
            var summary = await _scanner.StartScanAsync(SelectedMode, targets);
            HasCompletedSummary = true;
            StatusBanner = summary.Status == "Cancelled"
                ? $"Đã hủy phiên quét sau khi kiểm tra {summary.FilesScanned:N0} tệp."
                : summary.ThreatsFound > 0
                    ? $"Hoàn tất ({summary.Duration:mm\\:ss}): Đã quét {summary.FilesScanned:N0} tệp — phát hiện {summary.ThreatsFound} mối đe dọa!"
                    : $"Hoàn tất ({summary.Duration:mm\\:ss}): Đã quét {summary.FilesScanned:N0} tệp — Thiết bị hoàn toàn sạch!";

            await _appState.RefreshGlobalStateAsync();
        }
        catch (Exception ex)
        {
            StatusBanner = $"Lỗi trong quá trình quét: {ex.Message}";
        }
    }

    [RelayCommand]
    private void TogglePause()
    {
        if (!IsScanning) return;
        if (IsPaused)
        {
            _scanner.ResumeScan();
            IsPaused = false;
            StatusBanner = "Đã tiếp tục quét...";
        }
        else
        {
            _scanner.PauseScan();
            IsPaused = true;
            StatusBanner = "Phiên quét đang tạm dừng.";
        }
    }

    [RelayCommand]
    private void CancelScan()
    {
        if (!IsScanning) return;
        _scanner.CancelScan();
        StatusBanner = "Đang dừng phiên quét...";
    }

    [RelayCommand]
    private async Task QuarantineThreatAsync(DetectionItem? item)
    {
        if (item is null) return;
        await _quarantine.QuarantineFileAsync(item);
        item.ActionTaken = "Quarantined";
        DetectedThreats.Remove(item);
        StatusBanner = $"Đã mã hóa AES-256-GCM và chuyển {item.FileName} vào Khu cách ly.";
        await _appState.RefreshGlobalStateAsync();
    }

    [RelayCommand]
    private async Task QuarantineAllAsync()
    {
        var items = DetectedThreats.ToList();
        foreach (var item in items)
        {
            await _quarantine.QuarantineFileAsync(item);
            DetectedThreats.Remove(item);
        }
        StatusBanner = $"Đã cách ly an toàn {items.Count} mối đe dọa.";
        await _appState.RefreshGlobalStateAsync();
    }

    [RelayCommand]
    private async Task DeleteThreatFileAsync(DetectionItem? item)
    {
        if (item is null) return;
        try
        {
            if (File.Exists(item.FilePath))
            {
                File.SetAttributes(item.FilePath, FileAttributes.Normal);
                File.Delete(item.FilePath);
            }
            await _db.UpdateDetectionActionAsync(item.Id, "Deleted");
            await _db.AddActivityEventAsync(new ActivityEvent
            {
                EventType = ActivityEventType.FileDeleted,
                Title = "Đã xóa tệp nhiễm mã độc",
                Description = $"{item.FileName} ({item.ThreatName}) đã bị xóa trực tiếp",
                Severity = item.Severity
            });
            DetectedThreats.Remove(item);
            StatusBanner = $"Đã xóa tệp {item.FileName}.";
            await _appState.RefreshGlobalStateAsync();
        }
        catch (Exception ex)
        {
            StatusBanner = $"Không thể xóa {item.FileName}: {ex.Message}";
        }
    }

    [RelayCommand]
    private async Task ExcludeThreatAsync(DetectionItem? item)
    {
        if (item is null) return;
        await _db.AddExclusionAsync(new ExclusionItem
        {
            ExclusionType = "File",
            Value = item.FilePath,
            Reason = $"Người dùng bỏ qua cảnh báo ({item.ThreatName})"
        });
        await _db.UpdateDetectionActionAsync(item.Id, "Excluded");
        DetectedThreats.Remove(item);
        StatusBanner = $"Đã thêm {item.FileName} vào danh sách ngoại lệ.";
        await _appState.RefreshGlobalStateAsync();
    }

    [RelayCommand]
    private async Task LookupThreatIntelAsync(DetectionItem? item)
    {
        if (item is null) return;
        StatusBanner = $"Đang tra cứu Threat Intelligence cho {item.FileName} (SHA-256: {item.Sha256[..Math.Min(16, item.Sha256.Length)]}...)...";
        var res = await _threatIntel.LookupSha256Async(item.Sha256);
        item.ThreatIntelSummary = res.Summary;
        StatusBanner = $"[{res.Source}] {res.Summary}";
    }

    [RelayCommand]
    private void OpenVirusTotalWeb(DetectionItem? item)
    {
        if (item is null || string.IsNullOrWhiteSpace(item.Sha256)) return;
        try
        {
            var url = $"https://www.virustotal.com/gui/file/{item.Sha256}";
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(url) { UseShellExecute = true });
            StatusBanner = $"Đã mở trang tra cứu VirusTotal cho {item.FileName} trên trình duyệt.";
        }
        catch (Exception ex)
        {
            StatusBanner = $"Không thể mở trình duyệt: {ex.Message}";
        }
    }

    [RelayCommand]
    private async Task CreateAndScanSafeEicarTestAsync()
    {
        if (IsScanning) return;

        // Create a harmless Kryvnix YARA test sample (avoids collision with Windows Defender auto-deleting EICAR on disk)
        var demoDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "KryvnixAntivirus",
            "TestDemo");
        Directory.CreateDirectory(demoDir);
        var samplePath = Path.Combine(demoDir, "kryvnix_eicar_demo.bin");
        await File.WriteAllTextAsync(samplePath, "KRYVNIX-SIMULATED-THREAT-MARKER :: Harmless detection & AES-256-GCM quarantine test sample.");

        CustomTargets.Clear();
        CustomTargets.Add(demoDir);
        SelectedMode = ScanMode.Custom;
        await StartSelectedScanAsync();
    }
}
