using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using KryvnixAntivirus.Desktop.Data;
using KryvnixAntivirus.Desktop.Models;
using KryvnixAntivirus.Desktop.Services;

namespace KryvnixAntivirus.Desktop.ViewModels;

public partial class SettingsViewModel : ObservableObject
{
    private readonly ILocalDatabaseService _db;
    private readonly IEngineIpcClient _ipc;
    private readonly IBackendApiClient _api;
    private readonly IAppStateService _appState;

    [ObservableProperty] private bool _startWithWindows = true;
    [ObservableProperty] private bool _minimizeToTrayOnClose = true;
    [ObservableProperty] private bool _showDesktopNotifications = true;
    [ObservableProperty] private int _scanThreadCount = 4;
    [ObservableProperty] private int _maxFileSizeMb = 100;
    [ObservableProperty] private bool _scanArchives = true;
    [ObservableProperty] private int _heuristicThreshold = 65;
    [ObservableProperty] private string _defaultThreatAction = "Ask";
    [ObservableProperty] private bool _useNativeServiceWhenAvailable = true;
    [ObservableProperty] private string _namedPipeName = "KryvnixAntivirusPipe";
    [ObservableProperty] private string _backendApiBaseUrl = "http://localhost:8080/api/v1";
    [ObservableProperty] private string _deviceId = string.Empty;
    [ObservableProperty] private bool _simulateServiceUnavailable;

    [ObservableProperty] private string _engineModeLabel = string.Empty;
    [ObservableProperty] private int _pendingSyncCount;
    [ObservableProperty] private string _databasePath = string.Empty;
    [ObservableProperty] private string _statusMessage = string.Empty;

    public List<string> DefaultActionOptions { get; } = ["Ask", "AutoQuarantine", "LogOnly"];
    public int MaxThreadCount => Math.Max(4, Environment.ProcessorCount);

    public SettingsViewModel(
        ILocalDatabaseService db,
        IEngineIpcClient ipc,
        IBackendApiClient api,
        IAppStateService appState)
    {
        _db = db;
        _ipc = ipc;
        _api = api;
        _appState = appState;
        DatabasePath = _db.DatabasePath;
    }

    public async Task LoadAsync()
    {
        var s = await _db.LoadSettingsAsync();
        StartWithWindows = s.StartWithWindows;
        MinimizeToTrayOnClose = s.MinimizeToTrayOnClose;
        ShowDesktopNotifications = s.ShowDesktopNotifications;
        ScanThreadCount = s.ScanThreadCount;
        MaxFileSizeMb = s.MaxFileSizeMb;
        ScanArchives = s.ScanArchives;
        HeuristicThreshold = s.HeuristicThreshold;
        DefaultThreatAction = s.DefaultThreatAction;
        UseNativeServiceWhenAvailable = s.UseNativeServiceWhenAvailable;
        NamedPipeName = s.NamedPipeName;
        BackendApiBaseUrl = s.BackendApiBaseUrl;
        DeviceId = s.DeviceId;
        SimulateServiceUnavailable = s.SimulateServiceUnavailable;

        EngineModeLabel = _appState.EngineStatus.EngineModeLabel;
        PendingSyncCount = await _db.GetPendingSyncCountAsync();
    }

    [RelayCommand]
    private async Task SaveSettingsAsync()
    {
        var existing = await _db.LoadSettingsAsync();
        existing.StartWithWindows = StartWithWindows;
        existing.MinimizeToTrayOnClose = MinimizeToTrayOnClose;
        existing.ShowDesktopNotifications = ShowDesktopNotifications;
        existing.ScanThreadCount = ScanThreadCount;
        existing.MaxFileSizeMb = MaxFileSizeMb;
        existing.ScanArchives = ScanArchives;
        existing.HeuristicThreshold = HeuristicThreshold;
        existing.DefaultThreatAction = DefaultThreatAction;
        existing.UseNativeServiceWhenAvailable = UseNativeServiceWhenAvailable;
        existing.NamedPipeName = NamedPipeName.Trim();
        existing.BackendApiBaseUrl = BackendApiBaseUrl.Trim();
        existing.SimulateServiceUnavailable = SimulateServiceUnavailable;

        await _db.SaveSettingsAsync(existing);
        await _appState.RefreshGlobalStateAsync();
        EngineModeLabel = _appState.EngineStatus.EngineModeLabel;
        StatusMessage = "Đã lưu cấu hình thành công vào SQLite cục bộ.";
    }

    [RelayCommand]
    private async Task TestNamedPipeAsync()
    {
        var snap = await _ipc.CheckStatusAsync(NamedPipeName.Trim(), SimulateServiceUnavailable);
        EngineModeLabel = snap.EngineModeLabel;
        StatusMessage = snap.IsNativeServiceConnected
            ? $"Kết nối thành công tới C++ Native Service qua \\\\.\\pipe\\{NamedPipeName} (v{snap.EngineVersion})."
            : snap.IsEngineOperational
                ? $"Chưa phát hiện C++ Windows Service trên \\\\.\\pipe\\{NamedPipeName} — đang chạy bằng Local Hybrid Engine (.NET)."
                : "Chế độ mô phỏng Dịch vụ không khả dụng đang bật.";
    }

    [RelayCommand]
    private async Task SendHeartbeatAsync()
    {
        var ok = await _api.SendDeviceHeartbeatAsync();
        PendingSyncCount = await _db.GetPendingSyncCountAsync();
        StatusMessage = ok
            ? $"Đã gửi Device Heartbeat tới {BackendApiBaseUrl} thành công."
            : $"Backend API ngoại tuyến — payload đã lưu vào Offline Sync Queue ({PendingSyncCount} mục chờ đồng bộ).";
    }

    [RelayCommand]
    private async Task ResetSampleDataAsync()
    {
        var confirm = MessageBox.Show(
            "Khôi phục toàn bộ dữ liệu thống kê mẫu, lịch sử và cài đặt mặc định?",
            "Khôi phục dữ liệu mẫu",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);
        if (confirm != MessageBoxResult.Yes) return;

        await _db.ResetSampleDataAsync();
        await LoadAsync();
        await _appState.RefreshGlobalStateAsync();
        StatusMessage = "Đã khôi phục toàn bộ dữ liệu mẫu mặc định.";
    }
}
