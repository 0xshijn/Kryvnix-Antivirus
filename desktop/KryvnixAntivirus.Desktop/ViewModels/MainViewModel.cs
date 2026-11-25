using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using KryvnixAntivirus.Desktop.Data;
using KryvnixAntivirus.Desktop.Models;
using KryvnixAntivirus.Desktop.Services;

namespace KryvnixAntivirus.Desktop.ViewModels;

public partial class MainViewModel : ObservableObject
{
    private readonly IAppStateService _appState;
    private readonly ILocalDatabaseService _db;
    private readonly IRealtimeProtectionService _realtime;

    public DashboardViewModel DashboardVm { get; }
    public ScanViewModel ScanVm { get; }
    public RealtimeProtectionViewModel RealtimeVm { get; }
    public QuarantineViewModel QuarantineVm { get; }
    public HistoryViewModel HistoryVm { get; }
    public UpdatesViewModel UpdatesVm { get; }
    public SettingsViewModel SettingsVm { get; }

    [ObservableProperty] private NavigationPage _currentPage = NavigationPage.Dashboard;
    [ObservableProperty] private object? _currentViewModel;
    [ObservableProperty] private string _pageTitle = "Tổng quan";
    [ObservableProperty] private string _pageSubtitle = "Tình trạng bảo mật của thiết bị";
    [ObservableProperty] private string _pageIconKey = "IconHome";

    [ObservableProperty] private bool _isSidebarCollapsed;
    [ObservableProperty] private double _sidebarWidth = 240;

    [ObservableProperty] private bool _isProtectedState = true;
    [ObservableProperty] private string _sidebarStatusTitle = "Hệ thống được bảo vệ";
    [ObservableProperty] private string _sidebarRealtimeValue = "Bật";
    [ObservableProperty] private string _sidebarStatusAccentHex = "#22C55E";
    [ObservableProperty] private bool _hasPendingUpdate = true;

    [ObservableProperty] private int _unreadNotificationsCount;
    [ObservableProperty] private bool _isNotificationsOpen;
    [ObservableProperty] private bool _isAccountMenuOpen;

    [ObservableProperty] private string _userName = "Người dùng";
    [ObservableProperty] private string _userRole = "Standard";
    [ObservableProperty] private string _deviceId = string.Empty;
    [ObservableProperty] private string _engineModeLabel = string.Empty;

    public ObservableCollection<ActivityEvent> RecentNotifications { get; } = [];

    public bool IsDashboardSelected => CurrentPage == NavigationPage.Dashboard;
    public bool IsScanSelected => CurrentPage == NavigationPage.VirusScan;
    public bool IsRealtimeSelected => CurrentPage == NavigationPage.RealtimeProtection;
    public bool IsQuarantineSelected => CurrentPage == NavigationPage.Quarantine;
    public bool IsHistorySelected => CurrentPage == NavigationPage.ActivityHistory;
    public bool IsUpdatesSelected => CurrentPage == NavigationPage.Updates;
    public bool IsSettingsSelected => CurrentPage == NavigationPage.Settings;

    public MainViewModel(
        IAppStateService appState,
        ILocalDatabaseService db,
        IRealtimeProtectionService realtime,
        DashboardViewModel dashboardVm,
        ScanViewModel scanVm,
        RealtimeProtectionViewModel realtimeVm,
        QuarantineViewModel quarantineVm,
        HistoryViewModel historyVm,
        UpdatesViewModel updatesVm,
        SettingsViewModel settingsVm)
    {
        _appState = appState;
        _db = db;
        _realtime = realtime;

        DashboardVm = dashboardVm;
        ScanVm = scanVm;
        RealtimeVm = realtimeVm;
        QuarantineVm = quarantineVm;
        HistoryVm = historyVm;
        UpdatesVm = updatesVm;
        SettingsVm = settingsVm;

        _appState.StateRefreshed += (_, _) => Application.Current?.Dispatcher.InvokeAsync(SyncShellStateAsync);
        _appState.NavigationRequested += (_, page) => Application.Current?.Dispatcher.Invoke(() => Navigate(page));
        _appState.QuickScanTriggerRequested += (_, mode) => Application.Current?.Dispatcher.InvokeAsync(async () =>
        {
            Navigate(NavigationPage.VirusScan);
            await ScanVm.TriggerModeFromExternalAsync(mode);
        });
    }

    public async Task InitializeAsync()
    {
        Navigate(NavigationPage.Dashboard);
        await SyncShellStateAsync();
        await DashboardVm.LoadAsync();
    }

    partial void OnCurrentPageChanged(NavigationPage value)
    {
        OnPropertyChanged(nameof(IsDashboardSelected));
        OnPropertyChanged(nameof(IsScanSelected));
        OnPropertyChanged(nameof(IsRealtimeSelected));
        OnPropertyChanged(nameof(IsQuarantineSelected));
        OnPropertyChanged(nameof(IsHistorySelected));
        OnPropertyChanged(nameof(IsUpdatesSelected));
        OnPropertyChanged(nameof(IsSettingsSelected));
    }

    [RelayCommand]
    public void Navigate(NavigationPage page)
    {
        IsNotificationsOpen = false;
        IsAccountMenuOpen = false;
        CurrentPage = page;

        switch (page)
        {
            case NavigationPage.Dashboard:
                CurrentViewModel = DashboardVm;
                PageTitle = "Tổng quan";
                PageSubtitle = "Tình trạng bảo mật của thiết bị";
                PageIconKey = "IconHome";
                _ = DashboardVm.LoadAsync();
                break;

            case NavigationPage.VirusScan:
                CurrentViewModel = ScanVm;
                PageTitle = "Quét virus";
                PageSubtitle = "Kiểm tra mã độc bằng chữ ký SHA-256, YARA và phân tích Heuristic PE";
                PageIconKey = "IconSearch";
                break;

            case NavigationPage.RealtimeProtection:
                CurrentViewModel = RealtimeVm;
                PageTitle = "Bảo vệ thời gian thực";
                PageSubtitle = "Giám sát chủ động hệ thống tệp, tiến trình, mạng và hành vi bất thường";
                PageIconKey = "IconShieldCheck";
                _ = RealtimeVm.LoadAsync();
                break;

            case NavigationPage.Quarantine:
                CurrentViewModel = QuarantineVm;
                PageTitle = "Khu cách ly";
                PageSubtitle = "Kho lưu trữ cô lập mã hóa AES-256-GCM cho các tệp nguy hiểm";
                PageIconKey = "IconLock";
                _ = QuarantineVm.LoadAsync();
                break;

            case NavigationPage.ActivityHistory:
                CurrentViewModel = HistoryVm;
                PageTitle = "Lịch sử hoạt động";
                PageSubtitle = "Nhật ký chi tiết các sự kiện quét, phát hiện, cách ly và cập nhật";
                PageIconKey = "IconHistory";
                _ = HistoryVm.LoadAsync();
                break;

            case NavigationPage.Updates:
                CurrentViewModel = UpdatesVm;
                PageTitle = "Cập nhật";
                PageSubtitle = "Cơ sở dữ liệu chữ ký mã độc xác thực Ed25519 và quy tắc YARA";
                PageIconKey = "IconSync";
                _ = UpdatesVm.LoadAsync();
                break;

            case NavigationPage.Settings:
                CurrentViewModel = SettingsVm;
                PageTitle = "Cài đặt";
                PageSubtitle = "Cấu hình engine quét, dịch vụ Named Pipe IPC, API và chính sách hệ thống";
                PageIconKey = "IconSettings";
                _ = SettingsVm.LoadAsync();
                break;
        }
    }

    [RelayCommand]
    private void ToggleSidebar()
    {
        IsSidebarCollapsed = !IsSidebarCollapsed;
        SidebarWidth = IsSidebarCollapsed ? 72 : 240;
    }

    [RelayCommand]
    private async Task ToggleNotificationsAsync()
    {
        IsAccountMenuOpen = false;
        IsNotificationsOpen = !IsNotificationsOpen;
        if (IsNotificationsOpen)
        {
            await LoadNotificationsAsync();
        }
    }

    [RelayCommand]
    private async Task MarkAllNotificationsReadAsync()
    {
        await _db.MarkAllEventsReadAsync();
        await _appState.RefreshGlobalStateAsync();
        await LoadNotificationsAsync();
    }

    [RelayCommand]
    private void ToggleAccountMenu()
    {
        IsNotificationsOpen = false;
        IsAccountMenuOpen = !IsAccountMenuOpen;
    }

    private async Task LoadNotificationsAsync()
    {
        var events = await _db.GetActivityEventsAsync(8);
        RecentNotifications.Clear();
        foreach (var ev in events)
        {
            RecentNotifications.Add(ev);
        }
    }

    private async Task SyncShellStateAsync()
    {
        var state = _appState.CurrentProtectionState;
        IsProtectedState = state == ProtectionState.Protected;
        HasPendingUpdate = _appState.CurrentSettings.HasPendingUpdate;
        UnreadNotificationsCount = _appState.UnreadNotificationsCount;
        DeviceId = _appState.CurrentSettings.DeviceId;
        EngineModeLabel = _appState.EngineStatus.EngineModeLabel;

        (SidebarStatusTitle, SidebarStatusAccentHex) = state switch
        {
            ProtectionState.Protected => ("Hệ thống được bảo vệ", "#22C55E"),
            ProtectionState.AttentionRequired => ("Cần chú ý bảo mật", "#F59E0B"),
            ProtectionState.ThreatDetected => ("Phát hiện mối đe dọa", "#EF4444"),
            ProtectionState.ProtectionDisabled => ("Bảo vệ đang tắt", "#EF4444"),
            _ => ("Dịch vụ ngoại tuyến", "#64748B")
        };

        SidebarRealtimeValue = _realtime.CurrentState.IsMasterEnabled ? "Bật" : "Tắt";
        await LoadNotificationsAsync();
    }
}
