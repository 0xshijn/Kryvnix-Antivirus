using System.Collections.ObjectModel;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using KryvnixAntivirus.Desktop.Models;
using KryvnixAntivirus.Desktop.Services;
using Microsoft.Win32;

namespace KryvnixAntivirus.Desktop.ViewModels;

public partial class QuarantineViewModel : ObservableObject
{
    private readonly IQuarantineService _quarantine;
    private readonly IAppStateService _appState;
    private List<QuarantineItem> _allItems = [];

    [ObservableProperty] private string _searchQuery = string.Empty;
    [ObservableProperty] private string _selectedCategory = "Tất cả";
    [ObservableProperty] private int _totalCount;
    [ObservableProperty] private long _totalSizeBytes;
    [ObservableProperty] private string _statusMessage = string.Empty;
    [ObservableProperty] private string _vaultPath = string.Empty;

    public ObservableCollection<QuarantineItem> FilteredItems { get; } = [];
    public List<string> CategoryFilters { get; } = ["Tất cả", "Trojan", "Ransomware", "Spyware", "Worm", "Backdoor", "Adware", "Other"];

    public QuarantineViewModel(IQuarantineService quarantine, IAppStateService appState)
    {
        _quarantine = quarantine;
        _appState = appState;
        VaultPath = _quarantine.VaultDirectory;
    }

    partial void OnSearchQueryChanged(string value) => ApplyFilter();
    partial void OnSelectedCategoryChanged(string value) => ApplyFilter();

    [RelayCommand]
    public async Task LoadAsync()
    {
        _allItems = await _quarantine.GetAllItemsAsync();
        TotalCount = _allItems.Count;
        TotalSizeBytes = _allItems.Sum(i => i.FileSize);
        ApplyFilter();
    }

    private void ApplyFilter()
    {
        FilteredItems.Clear();
        var query = SearchQuery.Trim().ToLowerInvariant();

        foreach (var item in _allItems)
        {
            if (SelectedCategory != "Tất cả" && !item.Category.ToString().Equals(SelectedCategory, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!string.IsNullOrEmpty(query) &&
                !item.OriginalName.Contains(query, StringComparison.OrdinalIgnoreCase) &&
                !item.ThreatName.Contains(query, StringComparison.OrdinalIgnoreCase) &&
                !item.OriginalPath.Contains(query, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            FilteredItems.Add(item);
        }
    }

    [RelayCommand]
    private async Task RestoreItemAsync(QuarantineItem? item)
    {
        if (item is null) return;
        var confirm = MessageBox.Show(
            $"Bạn có chắc muốn giải mã và khôi phục '{item.OriginalName}' về vị trí cũ?\nChỉ khôi phục nếu bạn tin cậy tệp này.",
            "Xác nhận khôi phục tệp",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (confirm != MessageBoxResult.Yes) return;

        try
        {
            var dest = await _quarantine.RestoreFileAsync(item);
            StatusMessage = $"Đã khôi phục {item.OriginalName} về {dest}.";
            await LoadAsync();
            await _appState.RefreshGlobalStateAsync();
        }
        catch (Exception ex)
        {
            StatusMessage = $"Lỗi khi khôi phục: {ex.Message}";
        }
    }

    [RelayCommand]
    private async Task RestoreToCustomPathAsync(QuarantineItem? item)
    {
        if (item is null) return;
        var dlg = new SaveFileDialog
        {
            Title = "Chọn vị trí lưu tệp khôi phục",
            FileName = item.OriginalName
        };
        if (dlg.ShowDialog() != true) return;

        try
        {
            var dest = await _quarantine.RestoreFileAsync(item, dlg.FileName);
            StatusMessage = $"Đã khôi phục an toàn vào {dest}.";
            await LoadAsync();
            await _appState.RefreshGlobalStateAsync();
        }
        catch (Exception ex)
        {
            StatusMessage = $"Lỗi khi khôi phục: {ex.Message}";
        }
    }

    [RelayCommand]
    private async Task DeleteItemAsync(QuarantineItem? item)
    {
        if (item is null) return;
        var confirm = MessageBox.Show(
            $"Xóa vĩnh viễn '{item.OriginalName}' ({item.ThreatName}) khỏi Khu cách ly?\nHành động này không thể hoàn tác.",
            "Xác nhận xóa vĩnh viễn",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (confirm != MessageBoxResult.Yes) return;

        await _quarantine.DeletePermanentlyAsync(item);
        StatusMessage = $"Đã xóa vĩnh viễn {item.OriginalName}.";
        await LoadAsync();
        await _appState.RefreshGlobalStateAsync();
    }

    [RelayCommand]
    private async Task PurgeAllAsync()
    {
        if (_allItems.Count == 0) return;
        var confirm = MessageBox.Show(
            $"Xóa vĩnh viễn toàn bộ {_allItems.Count} tệp trong Khu cách ly?",
            "Dọn sạch Khu cách ly",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (confirm != MessageBoxResult.Yes) return;

        foreach (var item in _allItems.ToList())
        {
            await _quarantine.DeletePermanentlyAsync(item);
        }

        StatusMessage = "Đã dọn sạch toàn bộ Khu cách ly.";
        await LoadAsync();
        await _appState.RefreshGlobalStateAsync();
    }
}
