using System.Windows;
using KryvnixAntivirus.Desktop.Data;
using KryvnixAntivirus.Desktop.Models;
using KryvnixAntivirus.Desktop.Services;
using KryvnixAntivirus.Desktop.ViewModels;
using KryvnixAntivirus.Desktop.Views;
using Microsoft.Extensions.DependencyInjection;

namespace KryvnixAntivirus.Desktop;

public partial class App : Application
{
    private ServiceProvider? _serviceProvider;
    private MainWindow? _mainWindow;

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        var services = new ServiceCollection();
        ConfigureServices(services);
        _serviceProvider = services.BuildServiceProvider();

        // Initialize core backend services asynchronously before displaying main window
        var db = _serviceProvider.GetRequiredService<ILocalDatabaseService>();
        await db.InitializeAsync();

        var auth = _serviceProvider.GetRequiredService<IAuthService>();
        await auth.InitializeAsync();

        var realtime = _serviceProvider.GetRequiredService<IRealtimeProtectionService>();
        await realtime.InitializeAsync();

        var tray = _serviceProvider.GetRequiredService<ISystemTrayService>();
        tray.Initialize();

        var appState = _serviceProvider.GetRequiredService<IAppStateService>();
        await appState.RefreshGlobalStateAsync();

        var mainVm = _serviceProvider.GetRequiredService<MainViewModel>();
        await mainVm.InitializeAsync();

        _mainWindow = _serviceProvider.GetRequiredService<MainWindow>();
        _mainWindow.DataContext = mainVm;
        MainWindow = _mainWindow;

        tray.OpenRequested += (_, _) => Dispatcher.Invoke(ShowMainWindow);
        tray.QuickScanRequested += (_, _) => Dispatcher.Invoke(() =>
        {
            ShowMainWindow();
            appState.RequestScanLaunch(ScanMode.Quick);
        });
        tray.ToggleRealtimeRequested += (_, _) => Dispatcher.Invoke(async () =>
        {
            var cur = realtime.CurrentState;
            cur.IsMasterEnabled = !cur.IsMasterEnabled;
            await realtime.UpdateStateAsync(cur);
            await appState.RefreshGlobalStateAsync();
        });
        tray.ExitRequested += (_, _) => Dispatcher.Invoke(ExitApplication);

        realtime.ThreatIntercepted += (_, detection) => Dispatcher.Invoke(async () =>
        {
            if (appState.CurrentSettings.ShowDesktopNotifications)
            {
                tray.ShowBalloon(
                    "Kryvnix Antivirus — Phát hiện mối đe dọa",
                    $"{detection.FileName} ({detection.ThreatName}) — {detection.ActionTaken}",
                    isWarning: true);
            }
            await appState.RefreshGlobalStateAsync();
        });

        _mainWindow.Show();

        if (e.Args.Contains("--open-register", StringComparer.OrdinalIgnoreCase))
        {
            mainVm.AuthVm.Open(AuthDialogMode.Register);
        }

        // Handle Windows Explorer Right-Click Context Menu: --scan "<path>"
        int scanArgIdx = Array.FindIndex(e.Args, a => a.Equals("--scan", StringComparison.OrdinalIgnoreCase));
        if (scanArgIdx >= 0 && scanArgIdx + 1 < e.Args.Length)
        {
            var scanPath = e.Args[scanArgIdx + 1];
            mainVm.Navigate(NavigationPage.VirusScan);
            mainVm.ScanVm.AddTargetPath(scanPath);
            mainVm.ScanVm.SelectedMode = ScanMode.Custom;
            _ = mainVm.ScanVm.StartSelectedScanCommand.ExecuteAsync(null);
        }

        // Fire non-blocking background heartbeat to central backend
        _ = Task.Run(async () =>
        {
            var api = _serviceProvider.GetRequiredService<IBackendApiClient>();
            await api.SendDeviceHeartbeatAsync();
        });
    }

    private static void ConfigureServices(IServiceCollection services)
    {
        // Persistence & Core Services
        services.AddSingleton<ILocalDatabaseService, LocalDatabaseService>();
        services.AddSingleton<IAuthenticodeVerifier, AuthenticodeVerifier>();
        services.AddSingleton<IPeMlClassifierService, PeMlClassifierService>();
        services.AddSingleton<ISystemSecurityGuardService, SystemSecurityGuardService>();
        services.AddSingleton<IShellIntegrationService, ShellIntegrationService>();
        services.AddHttpClient<IThreatIntelligenceService, ThreatIntelligenceService>();
        services.AddSingleton<ILocalThreatAnalyzer, LocalThreatAnalyzer>();
        services.AddSingleton<IEngineIpcClient, NamedPipeEngineClient>();
        services.AddSingleton<IScanEngineService, HybridScanEngineService>();
        services.AddSingleton<IQuarantineService, EncryptedQuarantineService>();
        services.AddSingleton<IRealtimeProtectionService, RealtimeProtectionService>();
        services.AddSingleton<ISignatureUpdateService, SignatureUpdateService>();
        services.AddSingleton<ISystemTrayService, SystemTrayService>();
        services.AddSingleton<IAuthService, AuthService>();
        services.AddSingleton<IAppStateService, AppStateService>();
        services.AddHttpClient<IBackendApiClient, BackendApiClient>();

        // ViewModels
        services.AddSingleton<AuthViewModel>();
        services.AddSingleton<DashboardViewModel>();
        services.AddSingleton<ScanViewModel>();
        services.AddSingleton<RealtimeProtectionViewModel>();
        services.AddSingleton<QuarantineViewModel>();
        services.AddSingleton<HistoryViewModel>();
        services.AddSingleton<UpdatesViewModel>();
        services.AddSingleton<SettingsViewModel>();
        services.AddSingleton<MainViewModel>();

        // Main Window
        services.AddSingleton<MainWindow>();
    }

    public void ShowMainWindow()
    {
        if (_mainWindow is null) return;
        if (!_mainWindow.IsVisible) _mainWindow.Show();
        if (_mainWindow.WindowState == WindowState.Minimized) _mainWindow.WindowState = WindowState.Normal;
        _mainWindow.Activate();
    }

    public void ExitApplication()
    {
        if (_serviceProvider is not null)
        {
            _serviceProvider.GetService<IRealtimeProtectionService>()?.Dispose();
            _serviceProvider.GetService<ISystemTrayService>()?.Dispose();
            _serviceProvider.Dispose();
        }
        Shutdown();
    }
}
