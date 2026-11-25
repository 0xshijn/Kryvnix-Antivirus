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
    private readonly IAuthService _authService;
    private readonly AuthViewModel _authVm;
    private readonly IShellIntegrationService _shellIntegration;

    [ObservableProperty] private bool _isUserLoggedIn;
    [ObservableProperty] private string _accountDisplayName = "Chế độ khách (Chưa đăng nhập)";
    [ObservableProperty] private string _accountDetails = "Đăng ký tài khoản để bảo vệ cài đặt và đồng bộ thiết bị Kryvnix.";
    [ObservableProperty] private bool _enableAiPeClassifier = true;
    [ObservableProperty] private bool _enableTamperProtection;
    [ObservableProperty] private bool _enableContextMenuIntegration;
    [ObservableProperty] private string _virusTotalApiKey = string.Empty;

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
        IAppStateService appState,
        IAuthService authService,
        AuthViewModel authVm,
        IShellIntegrationService shellIntegration)
    {
        _db = db;
        _ipc = ipc;
        _api = api;
        _appState = appState;
        _authService = authService;
        _authVm = authVm;
        _shellIntegration = shellIntegration;
        DatabasePath = _db.DatabasePath;

        _authService.CurrentUserChanged += (_, _) => Application.Current?.Dispatcher.Invoke(SyncAccountInfo);
    }

    private void SyncAccountInfo()
    {
        var user = _authService.CurrentUser;
        if (user is null)
        {
            IsUserLoggedIn = false;
            AccountDisplayName = "Chế độ khách (Chưa đăng nhập)";
            AccountDetails = "Đăng ký tài khoản mới hoặc đăng nhập để quản lý bảo mật cá nhân.";
        }
        else
        {
            IsUserLoggedIn = true;
            AccountDisplayName = $"{user.FullName} (@{user.Username})";
            AccountDetails = $"{user.Email}  •  Gói: {user.Role}  •  Mật khẩu bảo vệ bằng PBKDF2-SHA256";
        }
    }

    [RelayCommand]
    private void OpenRegister() => _authVm.Open(AuthDialogMode.Register);

    [RelayCommand]
    private void OpenLogin() => _authVm.Open(AuthDialogMode.Login);

    [RelayCommand]
    private void OpenChangePassword() => _authVm.Open(AuthDialogMode.ChangePassword);

    [RelayCommand]
    private async Task LogoutAccountAsync()
    {
        await _authService.LogoutAsync();
        await _appState.RefreshGlobalStateAsync();
        StatusMessage = "Đã đăng xuất tài khoản khỏi thiết bị.";
    }

    public async Task LoadAsync()
    {
        SyncAccountInfo();
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
        EnableAiPeClassifier = s.EnableAiPeClassifier;
        EnableTamperProtection = s.EnableTamperProtection;
        EnableContextMenuIntegration = _shellIntegration.IsContextMenuRegistered();
        VirusTotalApiKey = s.VirusTotalApiKey;

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
        existing.EnableAiPeClassifier = EnableAiPeClassifier;
        existing.EnableTamperProtection = EnableTamperProtection;
        existing.EnableContextMenuIntegration = EnableContextMenuIntegration;
        existing.VirusTotalApiKey = VirusTotalApiKey.Trim();

        if (EnableContextMenuIntegration)
        {
            _shellIntegration.RegisterContextMenu();
        }
        else
        {
            _shellIntegration.UnregisterContextMenu();
        }

        await _db.SaveSettingsAsync(existing);
        await _appState.RefreshGlobalStateAsync();
        EngineModeLabel = _appState.EngineStatus.EngineModeLabel;
        StatusMessage = "Đã lưu cấu hình thành công (kèm cài đặt Shell Context Menu, AI PE & Tamper Protection).";
    }

    [RelayCommand]
    private async Task FlushSyncQueueAsync()
    {
        int flushed = await _api.FlushOfflineSyncQueueAsync();
        PendingSyncCount = await _db.GetPendingSyncCountAsync();
        StatusMessage = flushed > 0
            ? $"Đã đồng bộ thành công {flushed} bản ghi lên Backend API."
            : $"Không thể đồng bộ (còn {PendingSyncCount} mục chờ Backend API trực tuyến).";
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
