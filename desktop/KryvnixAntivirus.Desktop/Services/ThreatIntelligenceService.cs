using System.Net;
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
        _http.Timeout = TimeSpan.FromSeconds(6);
        if (!_http.DefaultRequestHeaders.UserAgent.Any())
        {
            _http.DefaultRequestHeaders.UserAgent.ParseAdd("KryvnixAntivirus/2.0");
        }
        _db = db;
    }

    public async Task<ThreatIntelResult> LookupSha256Async(string sha256, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(sha256))
        {
            return new ThreatIntelResult { Found = false, Summary = "Không có mã băm SHA-256 hợp lệ." };
        }

        sha256 = sha256.Trim().ToLowerInvariant();
        var shortHash = sha256.Length >= 16 ? sha256[..16] + "..." : sha256;

        // 1. Check local SQLite signature DB first (instant)
        var localSig = await _db.FindSignatureBySha256Async(sha256, ct);
        if (localSig is not null)
        {
            return new ThreatIntelResult
            {
                Found = true,
                Source = "Kryvnix Local CSDL",
                MalwareFamily = localSig.ThreatName,
                Summary = $"Khớp CSDL mã độc nội bộ: {localSig.ThreatName} ({localSig.Category} / {localSig.Severity})."
            };
        }

        // 2. Check optional VirusTotal v3 API if user configured an API key
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
                        Summary = $"VirusTotal: {malicious} engine báo độc hại, {suspicious} nghi vấn (SHA-256: {shortHash})."
                    };
                }
            }
            catch
            {
                // Fall through to CIRCL Hashlookup
            }
        }

        // 3. Query CIRCL Hashlookup (free public NIST NSRL / known-good intelligence, zero API key required!)
        try
        {
            using var resp = await _http.GetAsync($"https://hashlookup.circl.lu/lookup/sha256/{sha256}", ct);
            if (resp.IsSuccessStatusCode)
            {
                using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
                var fileName = doc.RootElement.TryGetProperty("FileName", out var fn) ? fn.GetString() : "Known Software";
                var trust = doc.RootElement.TryGetProperty("hashlookup:trust", out var tr) ? tr.GetInt32() : 50;
                return new ThreatIntelResult
                {
                    Found = false,
                    Source = "CIRCL NSRL (Online)",
                    MalwareFamily = "Known-Good",
                    Summary = $"CIRCL NSRL xác nhận phần mềm đã biết ({fileName}, độ tin cậy {trust}/100) — có thể thêm vào Ngoại lệ."
                };
            }

            if (resp.StatusCode == HttpStatusCode.NotFound)
            {
                return new ThreatIntelResult
                {
                    Found = false,
                    Source = "CIRCL NSRL (Online)",
                    Summary = $"Tệp không nằm trong danh sách phần mềm chuẩn đã xác minh (SHA-256: {shortHash}) — nên thận trọng hoặc mở VirusTotal để đối chiếu."
                };
            }
        }
        catch
        {
            // Network offline
        }

        return new ThreatIntelResult
        {
            Found = false,
            Source = "Local Analysis",
            Summary = $"Chưa kết nối được dịch vụ Intel trực tuyến (SHA-256: {shortHash}) — bấm 'VirusTotal' để kiểm tra trên trình duyệt."
        };
    }
}
