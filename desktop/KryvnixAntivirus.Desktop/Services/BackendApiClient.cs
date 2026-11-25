using System.Net.Http;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using KryvnixAntivirus.Desktop.Data;
using KryvnixAntivirus.Desktop.Models;

namespace KryvnixAntivirus.Desktop.Services;

public interface IBackendApiClient
{
    Task<bool> SendDeviceHeartbeatAsync(CancellationToken ct = default);
    Task ReportDetectionAsync(DetectionItem detection, CancellationToken ct = default);
    Task<int> FlushOfflineSyncQueueAsync(CancellationToken ct = default);
}

public sealed class BackendApiClient : IBackendApiClient
{
    private readonly HttpClient _httpClient;
    private readonly ILocalDatabaseService _db;

    public BackendApiClient(HttpClient httpClient, ILocalDatabaseService db)
    {
        _httpClient = httpClient;
        _httpClient.Timeout = TimeSpan.FromSeconds(4);
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
            agentVersion = "2.0.0",
            dbVersion = settings.DatabaseVersion,
            realtimeEnabled = realtime.IsMasterEnabled,
            timestamp = DateTime.UtcNow
        };

        try
        {
            var url = $"{settings.BackendApiBaseUrl.TrimEnd('/')}/devices/heartbeat";
            using var resp = await _httpClient.PostAsJsonAsync(url, payload, ct);
            if (resp.IsSuccessStatusCode)
            {
                await FlushOfflineSyncQueueAsync(ct);
                return true;
            }
            return false;
        }
        catch
        {
            await _db.EnqueueSyncPayloadAsync("/devices/heartbeat", JsonSerializer.Serialize(payload), ct);
            return false;
        }
    }

    public async Task ReportDetectionAsync(DetectionItem detection, CancellationToken ct = default)
    {
        var settings = await _db.LoadSettingsAsync(ct);
        var dto = new
        {
            deviceId = settings.DeviceId,
            fileName = detection.FileName,
            filePath = detection.FilePath,
            sha256 = detection.Sha256,
            threatName = detection.ThreatName,
            category = detection.Category.ToString(),
            severity = detection.Severity.ToString(),
            detectionMethod = detection.DetectionMethod,
            heuristicScore = detection.HeuristicScore,
            actionTaken = detection.ActionTaken
        };
        var json = JsonSerializer.Serialize(dto);

        try
        {
            var url = $"{settings.BackendApiBaseUrl.TrimEnd('/')}/detections";
            using var resp = await _httpClient.PostAsJsonAsync(url, dto, ct);
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

    public async Task<int> FlushOfflineSyncQueueAsync(CancellationToken ct = default)
    {
        var settings = await _db.LoadSettingsAsync(ct);
        var baseUrl = settings.BackendApiBaseUrl.TrimEnd('/');
        var queued = await _db.GetPendingSyncPayloadsAsync(50, ct);
        int synced = 0;

        foreach (var (id, endpoint, payloadJson) in queued)
        {
            try
            {
                var url = $"{baseUrl}/{endpoint.TrimStart('/')}";
                using var content = new StringContent(payloadJson, Encoding.UTF8, "application/json");
                using var resp = await _httpClient.PostAsync(url, content, ct);
                if (resp.IsSuccessStatusCode)
                {
                    await _db.DeleteSyncPayloadAsync(id, ct);
                    synced++;
                }
            }
            catch
            {
                break; // Backend offline
            }
        }

        return synced;
    }
}
