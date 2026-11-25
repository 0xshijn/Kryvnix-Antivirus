using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using KryvnixAntivirus.Desktop.Data;
using KryvnixAntivirus.Desktop.Models;
using KryvnixAntivirus.Desktop.Services;

namespace KryvnixAntivirus.Desktop.ViewModels;

public partial class UpdatesViewModel : ObservableObject
{
    private readonly ILocalDatabaseService _db;
    private readonly ISignatureUpdateService _updateService;
    private readonly IAppStateService _appState;

    [ObservableProperty] private string _databaseVersion = "v2025.01.15";
    [ObservableProperty] private long _totalSignatures;
    [ObservableProperty] private int _yaraRuleCount = 486;
    [ObservableProperty] private string _appVersion = "v2.0.0";
    [ObservableProperty] private bool _hasPendingUpdate = true;
    [ObservableProperty] private bool _isUpdating;
    [ObservableProperty] private int _updateProgress;
    [ObservableProperty] private string _updateStatusText = "Có bản cập nhật cơ sở dữ liệu mã độc mới sẵn sàng tải về.";
    [ObservableProperty] private string _ed25519BadgeText = "Ed25519 Đã xác thực";
    [ObservableProperty] private int _autoUpdateIntervalIndex = 1; // 4 giờ

    public List<string> AutoUpdateOptions { get; } = ["Mỗi 1 giờ", "Mỗi 4 giờ (Khuyến nghị)", "Mỗi 12 giờ", "Mỗi 24 giờ"];
    public ObservableCollection<UpdateHistoryItem> History { get; } = [];

    public UpdatesViewModel(
        ILocalDatabaseService db,
        ISignatureUpdateService updateService,
        IAppStateService appState)
    {
        _db = db;
        _updateService = updateService;
        _appState = appState;
    }

    public async Task LoadAsync()
    {
        var settings = await _db.LoadSettingsAsync();
        DatabaseVersion = settings.DatabaseVersion;
        HasPendingUpdate = settings.HasPendingUpdate;
        TotalSignatures = await _db.GetTotalSignatureCountAsync();
        AutoUpdateIntervalIndex = settings.AutoUpdateIntervalHours switch
        {
            1 => 0,
            4 => 1,
            12 => 2,
            _ => 3
        };

        if (!IsUpdating)
        {
            UpdateStatusText = HasPendingUpdate
                ? "Có bản cập nhật cơ sở dữ liệu chữ ký mới sẵn sàng cài đặt."
                : $"Cơ sở dữ liệu {DatabaseVersion} đang ở phiên bản mới nhất.";
        }

        var hist = await _db.GetUpdateHistoryAsync();
        History.Clear();
        foreach (var item in hist) History.Add(item);
    }

    partial void OnAutoUpdateIntervalIndexChanged(int value)
    {
        _ = SaveIntervalAsync(value);
    }

    private async Task SaveIntervalAsync(int index)
    {
        var settings = await _db.LoadSettingsAsync();
        settings.AutoUpdateIntervalHours = index switch { 0 => 1, 1 => 4, 2 => 12, _ => 24 };
        await _db.SaveSettingsAsync(settings);
    }

    [RelayCommand]
    private async Task CheckAndUpdateAsync()
    {
        if (IsUpdating) return;
        IsUpdating = true;
        UpdateProgress = 5;

        try
        {
            var progress = new Progress<(int Percent, string Status)>(p =>
            {
                UpdateProgress = p.Percent;
                UpdateStatusText = p.Status;
            });

            var result = await _updateService.CheckAndApplyUpdatesAsync(progress);
            Ed25519BadgeText = result.Ed25519Verified ? "Ed25519 Hợp lệ" : "Ed25519 Lỗi xác thực";
            UpdateStatusText = result.Message;

            if (result.Success && !result.AlreadyUpToDate)
            {
                YaraRuleCount += 14;
            }

            await LoadAsync();
            await _appState.RefreshGlobalStateAsync();
        }
        catch (Exception ex)
        {
            UpdateStatusText = $"Cập nhật thất bại: {ex.Message}";
        }
        finally
        {
            IsUpdating = false;
        }
    }
}
