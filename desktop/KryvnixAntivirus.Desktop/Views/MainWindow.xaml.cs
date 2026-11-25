using System.ComponentModel;
using System.Windows;
using System.Windows.Media;
using KryvnixAntivirus.Desktop.Services;
using KryvnixAntivirus.Desktop.ViewModels;

namespace KryvnixAntivirus.Desktop.Views;

public partial class MainWindow : Window
{
    private readonly IAppStateService _appState;
    private readonly ISystemTrayService _tray;
    private bool _notifiedTrayHint;

    public MainWindow(IAppStateService appState, ISystemTrayService tray)
    {
        InitializeComponent();
        _appState = appState;
        _tray = tray;

        StateChanged += OnWindowStateChanged;
        DataContextChanged += OnDataContextChanged;
        Loaded += OnWindowLoaded;
    }

    private void OnWindowLoaded(object sender, RoutedEventArgs e)
    {
        var workArea = SystemParameters.WorkArea;
        if (Width > workArea.Width - 24)
        {
            Width = Math.Max(MinWidth, workArea.Width - 24);
        }
        if (Height > workArea.Height - 24)
        {
            Height = Math.Max(MinHeight, workArea.Height - 24);
        }

        Left = workArea.Left + (workArea.Width - Width) / 2;
        Top = workArea.Top + (workArea.Height - Height) / 2;
    }

    private void OnDataContextChanged(object sender, DependencyPropertyChangedEventArgs e)
    {
        if (e.OldValue is INotifyPropertyChanged oldNpc)
        {
            oldNpc.PropertyChanged -= OnViewModelPropertyChanged;
        }
        if (e.NewValue is INotifyPropertyChanged newNpc)
        {
            newNpc.PropertyChanged += OnViewModelPropertyChanged;
            UpdateHeaderIcon();
        }
    }

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(MainViewModel.PageIconKey))
        {
            UpdateHeaderIcon();
        }
    }

    private void UpdateHeaderIcon()
    {
        if (DataContext is MainViewModel vm && TryFindResource(vm.PageIconKey) is Geometry geo)
        {
            HeaderPageIcon.Data = geo;
        }
    }

    private void OnWindowStateChanged(object? sender, EventArgs e)
    {
        if (WindowState == WindowState.Maximized)
        {
            WindowOuterBorder.Margin = new Thickness(7);
            if (TryFindResource("IconWinRestore") is Geometry g) MaxRestoreIcon.Data = g;
        }
        else
        {
            WindowOuterBorder.Margin = new Thickness(0);
            if (TryFindResource("IconWinMaximize") is Geometry g) MaxRestoreIcon.Data = g;
        }
    }

    private void MinimizeButton_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

    private void MaxRestoreButton_Click(object sender, RoutedEventArgs e)
    {
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e)
    {
        if (_appState.CurrentSettings.MinimizeToTrayOnClose)
        {
            HideToTray();
        }
        else
        {
            ((App)Application.Current).ExitApplication();
        }
    }

    private void HideToTrayMenu_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is MainViewModel vm) vm.IsAccountMenuOpen = false;
        HideToTray();
    }

    private void ExitAppMenu_Click(object sender, RoutedEventArgs e)
    {
        ((App)Application.Current).ExitApplication();
    }

    private void HideToTray()
    {
        Hide();
        if (!_notifiedTrayHint)
        {
            _notifiedTrayHint = true;
            _tray.ShowBalloon(
                "Kryvnix Antivirus vẫn đang bảo vệ",
                "Ứng dụng đã thu nhỏ xuống khay hệ thống. Nhấp đúp biểu tượng khiên để mở lại.");
        }
    }
}
