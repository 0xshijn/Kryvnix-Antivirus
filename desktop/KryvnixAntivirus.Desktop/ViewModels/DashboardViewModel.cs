using System.Collections.ObjectModel;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using KryvnixAntivirus.Desktop.Data;
using KryvnixAntivirus.Desktop.Models;
using KryvnixAntivirus.Desktop.Services;
using LiveChartsCore;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.SkiaSharpView.Painting;
using SkiaSharp;

namespace KryvnixAntivirus.Desktop.ViewModels;

public partial class DashboardViewModel : ObservableObject
{
    private readonly ILocalDatabaseService _db;
    private readonly IAppStateService _appState;
    private readonly IRealtimeProtectionService _realtime;
    private bool _suppressRealtimeWrite;

    [ObservableProperty] private ProtectionState _protectionState = ProtectionState.Protected;
    [ObservableProperty] private string _heroTitle = "Thiết bị an toàn";
    [ObservableProperty] private string _heroSubtitle = "Hệ thống đang được bảo vệ toàn diện";
    [ObservableProperty] private string _heroRealtimeText = "Đang bật";
    [ObservableProperty] private string _databaseVersion = "v2025.01.15";
    [ObservableProperty] private string _lastScanDisplay = "Hôm nay, 10:24";
    [ObservableProperty] private string _heroAccentHex = "#22C55E";
    [ObservableProperty] private string _heroBgStartHex = "#0E1C2A";
    [ObservableProperty] private string _heroBgMidHex = "#0D2B27";
    [ObservableProperty] private string _heroBgEndHex = "#113A2D";
    [ObservableProperty] private string _heroBorderHex = "#1E4639";
    [ObservableProperty] private bool _isHeroHealthy = true;

    [ObservableProperty] private int _selectedTimeRangeIndex = 1; // 7 ngày qua
    [ObservableProperty] private long _totalFilesScanned;
    [ObservableProperty] private int _threatsDetected;
    [ObservableProperty] private int _quarantinedFilesCount;
    [ObservableProperty] private long _databaseSignaturesCount;

    [ObservableProperty] private ISeries[] _threatChartSeries = [];
    public ObservableCollection<ThreatCategoryStat> ThreatBreakdown { get; } = [];
    public ObservableCollection<ActivityEvent> RecentActivities { get; } = [];

    [ObservableProperty] private bool _isRealtimeMasterEnabled = true;
    [ObservableProperty] private bool _isFileMonitorActive = true;
    [ObservableProperty] private bool _isProcessMonitorActive = true;
    [ObservableProperty] private bool _isNetworkShieldActive = true;
    [ObservableProperty] private bool _isBehaviorMonitorActive = true;

    public List<string> TimeRangeOptions { get; } =
    [
        "Hôm nay",
        "7 ngày qua",
        "30 ngày qua",
        "Tất cả"
    ];

    public DashboardViewModel(
        ILocalDatabaseService db,
        IAppStateService appState,
        IRealtimeProtectionService realtime)
    {
        _db = db;
        _appState = appState;
        _realtime = realtime;

        _appState.StateRefreshed += (_, _) => Application.Current?.Dispatcher.InvokeAsync(LoadAsync);
        _realtime.StateChanged += (_, state) => Application.Current?.Dispatcher.Invoke(() => SyncRealtimeFlags(state));
    }

    partial void OnSelectedTimeRangeIndexChanged(int value)
    {
        _ = LoadAsync();
    }

    partial void OnIsRealtimeMasterEnabledChanged(bool value)
    {
        if (_suppressRealtimeWrite) return;
        _ = ToggleMasterRealtimeAsync(value);
    }

    private async Task ToggleMasterRealtimeAsync(bool enabled)
    {
        var st = _realtime.CurrentState;
        st.IsMasterEnabled = enabled;
        await _realtime.UpdateStateAsync(st);
        await _appState.RefreshGlobalStateAsync();
    }

    public async Task LoadAsync()
    {
        var range = SelectedTimeRangeIndex switch
        {
            0 => TimeRangeFilter.Today,
            1 => TimeRangeFilter.Last7Days,
            2 => TimeRangeFilter.Last30Days,
            _ => TimeRangeFilter.AllTime
        };

        var stats = await _db.GetDashboardStatsAsync(range);
        var recent = await _db.GetActivityEventsAsync(3);

        TotalFilesScanned = stats.TotalFilesScanned;
        ThreatsDetected = stats.ThreatsDetected;
        QuarantinedFilesCount = stats.QuarantinedFilesCount;
        DatabaseSignaturesCount = stats.DatabaseSignaturesCount;
        DatabaseVersion = stats.DatabaseVersion;

        if (stats.LastScanTime is DateTime dt)
        {
            LastScanDisplay = dt.Date == DateTime.Today
                ? $"Hôm nay, {dt:HH:mm}"
                : dt.Date == DateTime.Today.AddDays(-1)
                    ? $"Hôm qua, {dt:HH:mm}"
                    : dt.ToString("dd/MM/yyyy, HH:mm");
        }
        else
        {
            LastScanDisplay = "Chưa thực hiện";
        }

        ApplyHeroVisualState(_appState.CurrentProtectionState, stats.ActiveThreatsCount);
        SyncRealtimeFlags(_realtime.CurrentState);

        ThreatBreakdown.Clear();
        var seriesList = new List<ISeries>();
        foreach (var item in stats.ThreatBreakdown)
        {
            ThreatBreakdown.Add(item);
            if (item.Count > 0)
            {
                seriesList.Add(new PieSeries<double>
                {
                    Values = [item.Count],
                    Name = item.DisplayName,
                    InnerRadius = 48,
                    MaxRadialColumnWidth = 24,
                    Fill = new SolidColorPaint(SKColor.Parse(item.ColorHex)),
                    HoverPushout = 5,
                    ToolTipLabelFormatter = point => $"{item.DisplayName}: {item.Count} ({item.Percentage:0.0}%)"
                });
            }
        }

        if (seriesList.Count == 0)
        {
            seriesList.Add(new PieSeries<double>
            {
                Values = [1],
                Name = "An toàn",
                InnerRadius = 56,
                MaxRadialColumnWidth = 26,
                Fill = new SolidColorPaint(SKColor.Parse("#1F3044")),
                IsHoverable = false
            });
        }

        ThreatChartSeries = seriesList.ToArray();

        RecentActivities.Clear();
        foreach (var ev in recent)
        {
            RecentActivities.Add(ev);
        }
    }

    private void SyncRealtimeFlags(RealtimeProtectionState state)
    {
        _suppressRealtimeWrite = true;
        try
        {
            IsRealtimeMasterEnabled = state.IsMasterEnabled;
            IsFileMonitorActive = state.IsMasterEnabled && state.FileMonitorEnabled;
            IsProcessMonitorActive = state.IsMasterEnabled && state.ProcessMonitorEnabled;
            IsNetworkShieldActive = state.IsMasterEnabled && state.NetworkShieldEnabled;
            IsBehaviorMonitorActive = state.IsMasterEnabled && state.BehaviorMonitorEnabled;
            HeroRealtimeText = state.IsMasterEnabled ? "Đang bật" : "Đã tắt";
        }
        finally
        {
            _suppressRealtimeWrite = false;
        }
    }

    private void ApplyHeroVisualState(ProtectionState state, int activeThreats)
    {
        ProtectionState = state;
        IsHeroHealthy = state == ProtectionState.Protected;

        switch (state)
        {
            case ProtectionState.Protected:
                HeroTitle = "Thiết bị an toàn";
                HeroSubtitle = "Hệ thống đang được bảo vệ toàn diện";
                HeroAccentHex = "#22C55E";
                HeroBgStartHex = "#0D1B2A";
                HeroBgMidHex = "#0C2C27";
                HeroBgEndHex = "#103D2F";
                HeroBorderHex = "#1D4D3D";
                break;

            case ProtectionState.AttentionRequired:
                HeroTitle = "Cần chú ý bảo mật";
                HeroSubtitle = "Một số mô-đun bảo vệ thời gian thực đang bị tắt";
                HeroAccentHex = "#F59E0B";
                HeroBgStartHex = "#1B1B24";
                HeroBgMidHex = "#2F2516";
                HeroBgEndHex = "#3E2E16";
                HeroBorderHex = "#684C1E";
                break;

            case ProtectionState.ThreatDetected:
                HeroTitle = "Phát hiện mối đe dọa!";
                HeroSubtitle = $"Có {activeThreats} mối đe dọa chưa được xử lý cần cách ly ngay";
                HeroAccentHex = "#EF4444";
                HeroBgStartHex = "#1E1420";
                HeroBgMidHex = "#381822";
                HeroBgEndHex = "#481B25";
                HeroBorderHex = "#7A2835";
                break;

            case ProtectionState.ProtectionDisabled:
                HeroTitle = "Bảo vệ thời gian thực đã tắt";
                HeroSubtitle = "Thiết bị có nguy cơ bị tấn công — bật lại bảo vệ ngay";
                HeroAccentHex = "#EF4444";
                HeroBgStartHex = "#1C141E";
                HeroBgMidHex = "#341720";
                HeroBgEndHex = "#421B24";
                HeroBorderHex = "#732533";
                break;

            default:
                HeroTitle = "Dịch vụ bảo vệ không khả dụng";
                HeroSubtitle = "Không thể kết nối tới Kryvnix Protection Engine";
                HeroAccentHex = "#94A3B8";
                HeroBgStartHex = "#121824";
                HeroBgMidHex = "#1B2330";
                HeroBgEndHex = "#242E3D";
                HeroBorderHex = "#3B4759";
                break;
        }
    }

    [RelayCommand]
    private void RunQuickScan() => _appState.RequestScanLaunch(ScanMode.Quick);

    [RelayCommand]
    private void RunFullScan() => _appState.RequestScanLaunch(ScanMode.Full);

    [RelayCommand]
    private void OpenCustomScan() => _appState.RequestScanLaunch(ScanMode.Custom);

    [RelayCommand]
    private void OpenUpdates() => _appState.RequestNavigation(NavigationPage.Updates);

    [RelayCommand]
    private void ViewAllHistory() => _appState.RequestNavigation(NavigationPage.ActivityHistory);

    [RelayCommand]
    private void OpenRealtimeSettings() => _appState.RequestNavigation(NavigationPage.RealtimeProtection);
}
