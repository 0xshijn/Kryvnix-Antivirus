using System.Net.Http;
using System.Text.Json;
using KryvnixAntivirus.Desktop.Data;
using KryvnixAntivirus.Desktop.Models;

namespace KryvnixAntivirus.Desktop.Services;

public interface IThreatIntelligenceService
{
    Task<ThreatIntelResult> LookupSha256Async(string sha256, CancellationToken ct = default);
}

public sealed class ThreatIntelligenceService : IThreatIntelligenceService
{
    private readonly HttpClient _http;
    private readonly ILocalDatabaseService _db;

    public ThreatIntelligenceService(HttpClient http, ILocalDatabaseService db)
    {
        _http = http;
        _http.Timeout = TimeSpan.FromSeconds(5);
        _db = db;
    }

    public async Task<ThreatIntelResult> LookupSha256Async(string sha256, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(sha256))
        {
            return new ThreatIntelResult { Found = false, Summary = "Không có mã băm SHA-256 hợp lệ." };
        }

        // 1. Check optional VirusTotal v3 if API key is configured
        var settings = await _db.LoadSettingsAsync(ct);
        if (!string.IsNullOrWhiteSpace(settings.VirusTotalApiKey))
        {
            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Get, $"https://www.virustotal.com/api/v3/files/{sha256}");
                req.Headers.Add("x-apikey", settings.VirusTotalApiKey.Trim());
                using var resp = await _http.SendAsync(req, ct);
                if (resp.IsSuccessStatusCode)
                {
                    using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
                    var stats = doc.RootElement.GetProperty("data").GetProperty("attributes").GetProperty("last_analysis_stats");
                    int malicious = stats.GetProperty("malicious").GetInt32();
                    int suspicious = stats.GetProperty("suspicious").GetInt32();
                    return new ThreatIntelResult
                    {
                        Found = malicious > 0 || suspicious > 0,
                        Source = "VirusTotal v3",
                        MalwareFamily = malicious > 0 ? "Detected on VirusTotal" : "Clean",
                        Summary = $"VirusTotal: {malicious} engine báo độc hại, {suspicious} nghi vấn."
                    };
                }
            }
            catch
            {
                // Fall through to MalwareBazaar
            }
        }

        // 2. Query MalwareBazaar public hash lookup (abuse.ch)
        try
        {
            using var content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["query"] = "get_info",
                ["hash"] = sha256
            });
            using var resp = await _http.PostAsync("https://mb-api.abuse.ch/api/v1/", content, ct);
            if (resp.IsSuccessStatusCode)
            {
                using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
                if (doc.RootElement.TryGetProperty("query_status", out var st) && st.GetString() == "ok" &&
                    doc.RootElement.TryGetProperty("data", out var dataArr) && dataArr.GetArrayLength() > 0)
                {
                    var first = dataArr[0];
                    var sig = first.TryGetProperty("signature", out var sProp) && sProp.ValueKind == JsonValueKind.String
                        ? sProp.GetString() ?? "Known Malware"
                        : "Known Malware";
                    return new ThreatIntelResult
                    {
                        Found = true,
                        Source = "MalwareBazaar (abuse.ch)",
                        MalwareFamily = sig,
                        Summary = $"MalwareBazaar xác nhận mẫu độc hại: {sig}"
                    };
                }

                return new ThreatIntelResult
                {
                    Found = false,
                    Source = "MalwareBazaar (abuse.ch)",
                    Summary = "Không tìm thấy mẫu khớp trên MalwareBazaar (có thể là mẫu thử nghiệm hoặc biến thể mới)."
                };
            }
        }
        catch
        {
            // Network offline or blocked
        }

        // 3. Fallback to local SQLite signature DB
        var localSig = await _db.FindSignatureBySha256Async(sha256, ct);
        if (localSig is not null)
        {
            return new ThreatIntelResult
            {
                Found = true,
                Source = "Kryvnix Local CSDL",
                MalwareFamily = localSig.ThreatName,
                Summary = $"Khớp CSDL nội bộ: {localSig.ThreatName} ({localSig.Category})"
            };
        }

        return new ThreatIntelResult
        {
            Found = false,
            Source = "Offline Fallback",
            Summary = "Không thể kết nối Threat Intel trực tuyến — chưa có bản ghi khớp cục bộ."
        };
    }
}
