using System.Collections.ObjectModel;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using KryvnixAntivirus.Desktop.Data;
using KryvnixAntivirus.Desktop.Models;
using KryvnixAntivirus.Desktop.Services;
using WinForms = System.Windows.Forms;

namespace KryvnixAntivirus.Desktop.ViewModels;

public partial class RealtimeProtectionViewModel : ObservableObject
{
    private readonly IRealtimeProtectionService _realtime;
    private readonly ILocalDatabaseService _db;
    private readonly IAppStateService _appState;
    private bool _suppressSave;

    [ObservableProperty] private bool _isMasterEnabled = true;
    [ObservableProperty] private bool _fileMonitorEnabled = true;
    [ObservableProperty] private bool _processMonitorEnabled = true;
    [ObservableProperty] private bool _networkShieldEnabled = true;
    [ObservableProperty] private bool _behaviorMonitorEnabled = true;
    [ObservableProperty] private bool _autoQuarantineRealtime = true;
    [ObservableProperty] private int _heuristicSensitivity = 2;

    [ObservableProperty] private string _newExclusionType = "Folder";
    [ObservableProperty] private string _newExclusionValue = string.Empty;
    [ObservableProperty] private string _newExclusionReason = string.Empty;

    public List<string> ExclusionTypes { get; } = ["Folder", "File", "Extension"];
    public ObservableCollection<ExclusionItem> Exclusions { get; } = [];
    public ObservableCollection<string> MonitoredPaths { get; } = [];
    public ObservableCollection<string> LiveMonitorLogs { get; } = [];

    public string SensitivityLabel => HeuristicSensitivity switch
    {
        1 => "Thấp (Ít cảnh báo giả)",
        3 => "Cao (Phát hiện nghiêm ngặt)",
        _ => "Cân bằng (Khuyến nghị)"
    };

    public RealtimeProtectionViewModel(
        IRealtimeProtectionService realtime,
        ILocalDatabaseService db,
        IAppStateService appState)
    {
        _realtime = realtime;
        _db = db;
        _appState = appState;

        _realtime.StateChanged += (_, st) => Application.Current?.Dispatcher.Invoke(() => ApplyStateToProperties(st));
        _realtime.MonitorActivityLogged += (_, line) => Application.Current?.Dispatcher.Invoke(() =>
        {
            LiveMonitorLogs.Insert(0, line);
            while (LiveMonitorLogs.Count > 50) LiveMonitorLogs.RemoveAt(LiveMonitorLogs.Count - 1);
        });
    }

    public async Task LoadAsync()
    {
        ApplyStateToProperties(_realtime.CurrentState);

        MonitoredPaths.Clear();
        foreach (var p in _realtime.MonitoredPaths) MonitoredPaths.Add(p);

        var exclusions = await _db.GetExclusionsAsync();
        Exclusions.Clear();
        foreach (var ex in exclusions) Exclusions.Add(ex);

        if (LiveMonitorLogs.Count == 0)
        {
            LiveMonitorLogs.Add($"[{DateTime.Now:HH:mm:ss}] Cảm biến FileSystemWatcher sẵn sàng ({MonitoredPaths.Count} thư mục được bảo vệ).");
        }
    }

    private void ApplyStateToProperties(RealtimeProtectionState st)
    {
        _suppressSave = true;
        try
        {
            IsMasterEnabled = st.IsMasterEnabled;
            FileMonitorEnabled = st.FileMonitorEnabled;
            ProcessMonitorEnabled = st.ProcessMonitorEnabled;
            NetworkShieldEnabled = st.NetworkShieldEnabled;
            BehaviorMonitorEnabled = st.BehaviorMonitorEnabled;
            AutoQuarantineRealtime = st.AutoQuarantineRealtime;
            HeuristicSensitivity = st.HeuristicSensitivity;
            OnPropertyChanged(nameof(SensitivityLabel));
        }
        finally
        {
            _suppressSave = false;
        }
    }

    private async Task PersistStateAsync()
    {
        if (_suppressSave) return;
        await _realtime.UpdateStateAsync(new RealtimeProtectionState
        {
            IsMasterEnabled = IsMasterEnabled,
            FileMonitorEnabled = FileMonitorEnabled,
            ProcessMonitorEnabled = ProcessMonitorEnabled,
            NetworkShieldEnabled = NetworkShieldEnabled,
            BehaviorMonitorEnabled = BehaviorMonitorEnabled,
            AutoQuarantineRealtime = AutoQuarantineRealtime,
            HeuristicSensitivity = HeuristicSensitivity
        });
        await _appState.RefreshGlobalStateAsync();
    }

    partial void OnIsMasterEnabledChanged(bool value) => _ = PersistStateAsync();
    partial void OnFileMonitorEnabledChanged(bool value) => _ = PersistStateAsync();
    partial void OnProcessMonitorEnabledChanged(bool value) => _ = PersistStateAsync();
    partial void OnNetworkShieldEnabledChanged(bool value) => _ = PersistStateAsync();
    partial void OnBehaviorMonitorEnabledChanged(bool value) => _ = PersistStateAsync();
    partial void OnAutoQuarantineRealtimeChanged(bool value) => _ = PersistStateAsync();
    partial void OnHeuristicSensitivityChanged(int value)
    {
        OnPropertyChanged(nameof(SensitivityLabel));
        _ = PersistStateAsync();
    }

    [RelayCommand]
    private void BrowseExclusionFolder()
    {
        using var dialog = new WinForms.FolderBrowserDialog { Description = "Chọn thư mục cần loại trừ khỏi quá trình quét" };
        if (dialog.ShowDialog() == WinForms.DialogResult.OK)
        {
            NewExclusionType = "Folder";
            NewExclusionValue = dialog.SelectedPath;
        }
    }

    [RelayCommand]
    private async Task AddExclusionAsync()
    {
        if (string.IsNullOrWhiteSpace(NewExclusionValue)) return;

        var item = new ExclusionItem
        {
            ExclusionType = NewExclusionType,
            Value = NewExclusionValue.Trim(),
            Reason = string.IsNullOrWhiteSpace(NewExclusionReason) ? "Người dùng thêm thủ công" : NewExclusionReason.Trim()
        };

        await _db.AddExclusionAsync(item);
        NewExclusionValue = string.Empty;
        NewExclusionReason = string.Empty;
        await LoadAsync();
    }

    [RelayCommand]
    private async Task RemoveExclusionAsync(ExclusionItem? item)
    {
        if (item is null) return;
        await _db.RemoveExclusionAsync(item.Id);
        Exclusions.Remove(item);
    }
}
