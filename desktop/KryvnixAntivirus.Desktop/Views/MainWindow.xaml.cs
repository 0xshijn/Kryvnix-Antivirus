using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using KryvnixAntivirus.Desktop.Services;
using KryvnixAntivirus.Desktop.ViewModels;

namespace KryvnixAntivirus.Desktop.Views;

public partial class MainWindow : Window
{
    private readonly IAppStateService _appState;
    private readonly ISystemTrayService _tray;
    private bool _notifiedTrayHint;

    private const int WmGetMinMaxInfo = 0x0024;
    private const uint MonitorDefaultToNearest = 0x00000002;

    [StructLayout(LayoutKind.Sequential)]
    private struct POINT { public int X; public int Y; }

    [StructLayout(LayoutKind.Sequential)]
    private struct MINMAXINFO
    {
        public POINT ptReserved;
        public POINT ptMaxSize;
        public POINT ptMaxPosition;
        public POINT ptMinTrackSize;
        public POINT ptMaxTrackSize;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct RECT { public int Left; public int Top; public int Right; public int Bottom; }

    [StructLayout(LayoutKind.Sequential)]
    private struct MONITORINFO
    {
        public int cbSize;
        public RECT rcMonitor;
        public RECT rcWork;
        public uint dwFlags;
    }

    [DllImport("user32.dll")]
    private static extern IntPtr MonitorFromWindow(IntPtr hwnd, uint dwFlags);

    [DllImport("user32.dll")]
    private static extern bool GetMonitorInfo(IntPtr hMonitor, ref MONITORINFO lpmi);

    public MainWindow(IAppStateService appState, ISystemTrayService tray)
    {
        InitializeComponent();
        _appState = appState;
        _tray = tray;

        StateChanged += OnWindowStateChanged;
        DataContextChanged += OnDataContextChanged;
        Loaded += OnWindowLoaded;
        SourceInitialized += OnSourceInitialized;
    }

    private void OnSourceInitialized(object? sender, EventArgs e)
    {
        var handle = new WindowInteropHelper(this).Handle;
        HwndSource.FromHwnd(handle)?.AddHook(WindowProc);
    }

    private IntPtr WindowProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if (msg == WmGetMinMaxInfo)
        {
            WmGetMinMaxInfoHandler(hwnd, lParam);
            handled = true;
        }
        return IntPtr.Zero;
    }

    private static void WmGetMinMaxInfoHandler(IntPtr hwnd, IntPtr lParam)
    {
        var mmi = Marshal.PtrToStructure<MINMAXINFO>(lParam);
        var monitor = MonitorFromWindow(hwnd, MonitorDefaultToNearest);
        if (monitor != IntPtr.Zero)
        {
            var monitorInfo = new MONITORINFO { cbSize = Marshal.SizeOf<MONITORINFO>() };
            if (GetMonitorInfo(monitor, ref monitorInfo))
            {
                var rcWork = monitorInfo.rcWork;
                var rcMonitor = monitorInfo.rcMonitor;
                mmi.ptMaxPosition.X = Math.Abs(rcWork.Left - rcMonitor.Left);
                mmi.ptMaxPosition.Y = Math.Abs(rcWork.Top - rcMonitor.Top);
                mmi.ptMaxSize.X = Math.Abs(rcWork.Right - rcWork.Left);
                mmi.ptMaxSize.Y = Math.Abs(rcWork.Bottom - rcWork.Top);
            }
        }
        Marshal.StructureToPtr(mmi, lParam, true);
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
            WindowOuterBorder.Margin = new Thickness(0);
            WindowOuterBorder.BorderThickness = new Thickness(0);
            if (TryFindResource("IconWinRestore") is Geometry g) MaxRestoreIcon.Data = g;
        }
        else
        {
            WindowOuterBorder.Margin = new Thickness(0);
            WindowOuterBorder.BorderThickness = new Thickness(1);
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
