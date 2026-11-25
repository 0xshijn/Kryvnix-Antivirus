using System.Collections.ObjectModel;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using KryvnixAntivirus.Desktop.Data;
using KryvnixAntivirus.Desktop.Models;
using KryvnixAntivirus.Desktop.Services;
using Microsoft.Win32;

namespace KryvnixAntivirus.Desktop.ViewModels;

public partial class HistoryViewModel : ObservableObject
{
    private readonly ILocalDatabaseService _db;
    private readonly IAppStateService _appState;

    [ObservableProperty] private string _searchQuery = string.Empty;
    [ObservableProperty] private string _selectedFilterKey = "All";
    [ObservableProperty] private int _selectedTimeRangeIndex = 3; // All time
    [ObservableProperty] private string _statusMessage = string.Empty;

    public ObservableCollection<ActivityEvent> Events { get; } = [];
    public List<string> TimeRangeOptions { get; } = ["Hôm nay", "7 ngày qua", "30 ngày qua", "Tất cả"];

    public HistoryViewModel(ILocalDatabaseService db, IAppStateService appState)
    {
        _db = db;
        _appState = appState;
    }

    partial void OnSearchQueryChanged(string value) => _ = LoadAsync();
    partial void OnSelectedTimeRangeIndexChanged(int value) => _ = LoadAsync();

    [RelayCommand]
    private async Task SetFilterAsync(string filterKey)
    {
        SelectedFilterKey = filterKey;
        await LoadAsync();
    }

    [RelayCommand]
    public async Task LoadAsync()
    {
        ActivityEventType? typeFilter = SelectedFilterKey switch
        {
            "Scan" => ActivityEventType.ScanCompleted,
            "Threat" => ActivityEventType.MalwareDetected,
            "Quarantine" => ActivityEventType.FileQuarantined,
            "Update" => ActivityEventType.DatabaseUpdated,
            "Protection" => ActivityEventType.ProtectionChanged,
            _ => null
        };

        var range = SelectedTimeRangeIndex switch
        {
            0 => TimeRangeFilter.Today,
            1 => TimeRangeFilter.Last7Days,
            2 => TimeRangeFilter.Last30Days,
            _ => TimeRangeFilter.AllTime
        };

        var list = await _db.GetActivityEventsAsync(250, typeFilter, range, SearchQuery);
        Events.Clear();
        foreach (var ev in list) Events.Add(ev);
    }

    [RelayCommand]
    private async Task ExportCsvAsync()
    {
        var dlg = new SaveFileDialog
        {
            Title = "Xuất lịch sử bảo mật sang CSV",
            FileName = $"kryvnix_history_{DateTime.Now:yyyyMMdd_HHmm}.csv",
            Filter = "CSV File (*.csv)|*.csv"
        };
        if (dlg.ShowDialog() != true) return;

        var sb = new StringBuilder();
        sb.AppendLine("Timestamp,Type,Severity,Title,Description");
        foreach (var e in Events)
        {
            sb.AppendLine($"\"{e.CreatedAt:yyyy-MM-dd HH:mm:ss}\",\"{e.EventType}\",\"{e.Severity}\",\"{e.Title.Replace("\"", "\"\"")}\",\"{e.Description.Replace("\"", "\"\"")}\"");
        }

        await File.WriteAllTextAsync(dlg.FileName, sb.ToString(), Encoding.UTF8);
        StatusMessage = $"Đã xuất {Events.Count} bản ghi ra {dlg.FileName}";
    }

    [RelayCommand]
    private async Task ExportJsonAsync()
    {
        var dlg = new SaveFileDialog
        {
            Title = "Xuất lịch sử bảo mật sang JSON",
            FileName = $"kryvnix_history_{DateTime.Now:yyyyMMdd_HHmm}.json",
            Filter = "JSON File (*.json)|*.json"
        };
        if (dlg.ShowDialog() != true) return;

        var json = JsonSerializer.Serialize(Events, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(dlg.FileName, json, Encoding.UTF8);
        StatusMessage = $"Đã xuất {Events.Count} bản ghi JSON ra {dlg.FileName}";
    }

    [RelayCommand]
    private async Task ClearHistoryAsync()
    {
        if (Events.Count == 0) return;
        var confirm = MessageBox.Show("Xóa toàn bộ nhật ký lịch sử hoạt động?", "Xác nhận xóa lịch sử", MessageBoxButton.YesNo, MessageBoxImage.Question);
        if (confirm != MessageBoxResult.Yes) return;

        await _db.ClearActivityEventsAsync();
        await LoadAsync();
        await _appState.RefreshGlobalStateAsync();
        StatusMessage = "Đã xóa lịch sử hoạt động.";
    }
}
