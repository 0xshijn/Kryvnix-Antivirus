using KryvnixAntivirus.Desktop.Data;
using KryvnixAntivirus.Desktop.Models;

namespace KryvnixAntivirus.Desktop.Services;

public interface IAppStateService
{
    ProtectionState CurrentProtectionState { get; }
    EngineStatusSnapshot EngineStatus { get; }
    AppSettings CurrentSettings { get; }
    int UnreadNotificationsCount { get; }

    event EventHandler? StateRefreshed;
    event EventHandler<NavigationPage>? NavigationRequested;
    event EventHandler<ScanMode>? QuickScanTriggerRequested;

    Task RefreshGlobalStateAsync(CancellationToken ct = default);
    void RequestNavigation(NavigationPage page);
    void RequestScanLaunch(ScanMode mode);
    ProtectionState EvaluateProtectionState(EngineStatusSnapshot engine, RealtimeProtectionState realtime, int activeThreats, AppSettings settings);
}

public sealed class AppStateService : IAppStateService
{
    private readonly ILocalDatabaseService _db;
    private readonly IEngineIpcClient _ipc;
    private readonly IRealtimeProtectionService _realtime;
    private readonly ISystemTrayService _tray;

    public ProtectionState CurrentProtectionState { get; private set; } = ProtectionState.Protected;
    public EngineStatusSnapshot EngineStatus { get; private set; } = new();
    public AppSettings CurrentSettings { get; private set; } = new();
    public int UnreadNotificationsCount { get; private set; }

    public event EventHandler? StateRefreshed;
    public event EventHandler<NavigationPage>? NavigationRequested;
    public event EventHandler<ScanMode>? QuickScanTriggerRequested;

    public AppStateService(
        ILocalDatabaseService db,
        IEngineIpcClient ipc,
        IRealtimeProtectionService realtime,
        ISystemTrayService tray)
    {
        _db = db;
        _ipc = ipc;
        _realtime = realtime;
        _tray = tray;
    }

    public ProtectionState EvaluateProtectionState(
        EngineStatusSnapshot engine,
        RealtimeProtectionState realtime,
        int activeThreats,
        AppSettings settings)
    {
        if (!engine.IsEngineOperational)
        {
            return ProtectionState.ServiceUnavailable;
        }

        if (activeThreats > 0)
        {
            return ProtectionState.ThreatDetected;
        }

        if (!realtime.IsMasterEnabled)
        {
            return ProtectionState.ProtectionDisabled;
        }

        if (!realtime.FileMonitorEnabled || !realtime.BehaviorMonitorEnabled || !realtime.NetworkShieldEnabled || !realtime.ProcessMonitorEnabled)
        {
            return ProtectionState.AttentionRequired;
        }

        return ProtectionState.Protected;
    }

    public async Task RefreshGlobalStateAsync(CancellationToken ct = default)
    {
        CurrentSettings = await _db.LoadSettingsAsync(ct);
        EngineStatus = await _ipc.CheckStatusAsync(CurrentSettings.NamedPipeName, CurrentSettings.SimulateServiceUnavailable, ct);
        EngineStatus.DatabaseVersion = CurrentSettings.DatabaseVersion;

        var activeThreats = await _db.GetActiveUnresolvedThreatCountAsync(ct);
        var realtimeState = _realtime.CurrentState;
        CurrentProtectionState = EvaluateProtectionState(EngineStatus, realtimeState, activeThreats, CurrentSettings);

        var recentEvents = await _db.GetActivityEventsAsync(50, ct: ct);
        UnreadNotificationsCount = recentEvents.Count(e => !e.IsRead);

        var trayText = CurrentProtectionState switch
        {
            ProtectionState.Protected => "Thiết bị an toàn",
            ProtectionState.AttentionRequired => "Cần chú ý bảo mật",
            ProtectionState.ThreatDetected => $"Phát hiện {activeThreats} mối đe dọa",
            ProtectionState.ProtectionDisabled => "Bảo vệ đang tắt",
            _ => "Dịch vụ không khả dụng"
        };
        _tray.UpdateStatusTooltip(trayText, CurrentProtectionState == ProtectionState.Protected);

        StateRefreshed?.Invoke(this, EventArgs.Empty);
    }

    public void RequestNavigation(NavigationPage page) => NavigationRequested?.Invoke(this, page);
    public void RequestScanLaunch(ScanMode mode) => QuickScanTriggerRequested?.Invoke(this, mode);
}
