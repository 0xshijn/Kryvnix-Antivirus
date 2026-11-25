using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using KryvnixAntivirus.Desktop.Data;
using KryvnixAntivirus.Desktop.Models;

namespace KryvnixAntivirus.Desktop.Services;

public interface IBackendApiClient
{
    Task<bool> SendDeviceHeartbeatAsync(CancellationToken ct = default);
    Task ReportDetectionAsync(DetectionItem detection, CancellationToken ct = default);
}

public sealed class BackendApiClient : IBackendApiClient
{
    private readonly HttpClient _httpClient;
    private readonly ILocalDatabaseService _db;

    public BackendApiClient(HttpClient httpClient, ILocalDatabaseService db)
    {
        _httpClient = httpClient;
        _httpClient.Timeout = TimeSpan.FromSeconds(3);
        _db = db;
    }

    public async Task<bool> SendDeviceHeartbeatAsync(CancellationToken ct = default)
    {
        var settings = await _db.LoadSettingsAsync(ct);
        var realtime = await _db.LoadRealtimeStateAsync(ct);
        var payload = new
        {
            deviceId = settings.DeviceId,
            hostname = Environment.MachineName,
            osVersion = Environment.OSVersion.ToString(),
            agentVersion = "1.0.0",
            dbVersion = settings.DatabaseVersion,
            realtimeEnabled = realtime.IsMasterEnabled,
            timestamp = DateTime.UtcNow
        };

        try
        {
            var url = $"{settings.BackendApiBaseUrl.TrimEnd('/')}/devices/heartbeat";
            using var resp = await _httpClient.PostAsJsonAsync(url, payload, ct);
            return resp.IsSuccessStatusCode;
        }
        catch
        {
            // Backend server offline - store in offline sync queue safely
            await _db.EnqueueSyncPayloadAsync("/devices/heartbeat", JsonSerializer.Serialize(payload), ct);
            return false;
        }
    }

    public async Task ReportDetectionAsync(DetectionItem detection, CancellationToken ct = default)
    {
        var settings = await _db.LoadSettingsAsync(ct);
        var json = JsonSerializer.Serialize(detection);

        try
        {
            var url = $"{settings.BackendApiBaseUrl.TrimEnd('/')}/detections";
            using var resp = await _httpClient.PostAsJsonAsync(url, detection, ct);
            if (!resp.IsSuccessStatusCode)
            {
                await _db.EnqueueSyncPayloadAsync("/detections", json, ct);
            }
        }
        catch
        {
            await _db.EnqueueSyncPayloadAsync("/detections", json, ct);
        }
    }
}
