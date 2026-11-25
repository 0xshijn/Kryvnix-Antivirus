using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Data.Sqlite;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.UseUrls(builder.Configuration["Urls"] ?? "http://0.0.0.0:8080");

var jwtSecret = builder.Configuration["Jwt:Secret"] ?? "KryvnixAntivirusSuperSecretJwtSigningKey2026!@#";
var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret));

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(opt =>
    {
        opt.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = "KryvnixAntivirus.Api",
            ValidAudience = "KryvnixAntivirus.Clients",
            IssuerSigningKey = signingKey
        };
    });

builder.Services.AddAuthorization();
builder.Services.AddSignalR();
builder.Services.AddSingleton<CentralStore>();
builder.Services.AddCors(opt =>
{
    opt.AddDefaultPolicy(p => p
        .SetIsOriginAllowed(_ => true)
        .AllowAnyHeader()
        .AllowAnyMethod()
        .AllowCredentials());
});

var app = builder.Build();
app.UseCors();
app.UseAuthentication();
app.UseAuthorization();

var store = app.Services.GetRequiredService<CentralStore>();
await store.InitializeAsync();

app.MapHub<SecurityHub>("/hubs/security");

app.MapGet("/api/v1/health", () => Results.Ok(new
{
    status = "healthy",
    service = "Kryvnix Antivirus Central API",
    version = "2.0.0",
    timestamp = DateTime.UtcNow
}));

// ==================== AUTH & RBAC ====================
app.MapPost("/api/v1/auth/register", async (RegisterRequest req, CentralStore db) =>
{
    if (string.IsNullOrWhiteSpace(req.Username) || string.IsNullOrWhiteSpace(req.Email) || string.IsNullOrWhiteSpace(req.Password) || req.Password.Length < 8)
    {
        return Results.BadRequest(new { error = "Thông tin đăng ký không hợp lệ (mật khẩu >= 8 ký tự)." });
    }

    var created = await db.CreateUserAsync(req.Username.Trim(), req.Email.Trim(), req.FullName?.Trim() ?? req.Username, req.Password, "Standard");
    if (created is null)
    {
        return Results.Conflict(new { error = "Tên đăng nhập hoặc email đã tồn tại." });
    }

    await db.LogAuditAsync(created.Username, "USER_REGISTER", $"Registered account {created.Email}");
    var token = GenerateJwt(created, signingKey);
    return Results.Ok(new { token, user = new { created.Id, created.Username, created.Email, created.FullName, created.Role } });
});

app.MapPost("/api/v1/auth/login", async (LoginRequest req, CentralStore db) =>
{
    var user = await db.VerifyUserAsync(req.UsernameOrEmail, req.Password);
    if (user is null)
    {
        return Results.Unauthorized();
    }

    await db.LogAuditAsync(user.Username, "USER_LOGIN", "Authenticated via JWT");
    var token = GenerateJwt(user, signingKey);
    return Results.Ok(new { token, user = new { user.Id, user.Username, user.Email, user.FullName, user.Role } });
});

// ==================== DASHBOARD & FLEET SUMMARY ====================
app.MapGet("/api/v1/dashboard/summary", async (CentralStore db) => Results.Ok(await db.GetFleetSummaryAsync()));

// ==================== ENDPOINT / DEVICE MANAGEMENT ====================
app.MapGet("/api/v1/devices", async (CentralStore db) => Results.Ok(await db.GetDevicesAsync()));

app.MapPost("/api/v1/devices/heartbeat", async (HeartbeatRequest req, CentralStore db, IHubContext<SecurityHub> hub) =>
{
    var device = await db.UpsertDeviceHeartbeatAsync(req);
    await hub.Clients.All.SendAsync("DeviceUpdated", device);
    return Results.Ok(new { ok = true, device, pendingCommands = await db.ConsumePendingCommandsAsync(req.DeviceId) });
});

app.MapPost("/api/v1/devices/{deviceId}/remote-scan", async (string deviceId, RemoteScanRequest req, CentralStore db, IHubContext<SecurityHub> hub) =>
{
    await db.QueueRemoteCommandAsync(deviceId, $"SCAN:{req.Mode}");
    await db.LogAuditAsync("admin", "REMOTE_SCAN", $"Dispatched {req.Mode} scan to {deviceId}");
    await hub.Clients.All.SendAsync("RemoteScanRequested", new { deviceId, mode = req.Mode, issuedAt = DateTime.UtcNow });
    return Results.Ok(new { ok = true, message = $"Đã gửi lệnh quét {req.Mode} tới thiết bị {deviceId}." });
});

// ==================== MALWARE SIGNATURES CRUD ====================
app.MapGet("/api/v1/signatures", async (CentralStore db) => Results.Ok(await db.GetSignaturesAsync()));

app.MapPost("/api/v1/signatures", async (CreateSignatureRequest req, CentralStore db) =>
{
    if (string.IsNullOrWhiteSpace(req.Sha256) || string.IsNullOrWhiteSpace(req.ThreatName))
    {
        return Results.BadRequest(new { error = "SHA-256 và Tên mối đe dọa là bắt buộc." });
    }
    var item = await db.AddSignatureAsync(req);
    await db.LogAuditAsync("admin", "SIGNATURE_ADD", $"{req.ThreatName} ({req.Sha256[..Math.Min(12, req.Sha256.Length)]})");
    return Results.Ok(item);
});

app.MapDelete("/api/v1/signatures/{id:long}", async (long id, CentralStore db) =>
{
    await db.DeleteSignatureAsync(id);
    await db.LogAuditAsync("admin", "SIGNATURE_DELETE", $"Deleted signature #{id}");
    return Results.Ok(new { ok = true });
});

// ==================== YARA RULES CRUD ====================
app.MapGet("/api/v1/yara", async (CentralStore db) => Results.Ok(await db.GetYaraRulesAsync()));

app.MapPost("/api/v1/yara", async (CreateYaraRequest req, CentralStore db) =>
{
    var rule = await db.AddYaraRuleAsync(req);
    await db.LogAuditAsync("admin", "YARA_ADD", req.RuleName);
    return Results.Ok(rule);
});

app.MapPatch("/api/v1/yara/{id:long}/toggle", async (long id, CentralStore db) =>
{
    await db.ToggleYaraRuleAsync(id);
    return Results.Ok(new { ok = true });
});

app.MapDelete("/api/v1/yara/{id:long}", async (long id, CentralStore db) =>
{
    await db.DeleteYaraRuleAsync(id);
    return Results.Ok(new { ok = true });
});

// ==================== DETECTIONS & TELEMETRY ====================
app.MapGet("/api/v1/detections", async (CentralStore db) => Results.Ok(await db.GetDetectionsAsync()));

app.MapPost("/api/v1/detections", async (DetectionReportRequest req, CentralStore db, IHubContext<SecurityHub> hub) =>
{
    var saved = await db.AddDetectionAsync(req);
    await db.LogAuditAsync(req.DeviceId, "DETECTION_REPORTED", $"{req.ThreatName} on {req.FileName}");
    await hub.Clients.All.SendAsync("DetectionAlert", saved);
    return Results.Ok(saved);
});

// ==================== ED25519 SIGNED SIGNATURE UPDATE FEED ====================
app.MapGet("/api/v1/updates/latest", async (CentralStore db) =>
{
    var sigs = await db.GetSignaturesAsync();
    var version = $"v{DateTime.UtcNow:yyyy.MM.dd}";
    var payloadJson = JsonSerializer.Serialize(new { version, count = sigs.Count, signatures = sigs });
    var (sigBase64, pubBase64) = db.SignPayloadEd25519(Encoding.UTF8.GetBytes(payloadJson));

    return Results.Ok(new
    {
        version,
        signatureCount = sigs.Count,
        ed25519PublicKey = pubBase64,
        ed25519Signature = sigBase64,
        publishedAt = DateTime.UtcNow,
        signatures = sigs
    });
});

// ==================== AUDIT LOGS ====================
app.MapGet("/api/v1/audit", async (CentralStore db) => Results.Ok(await db.GetAuditLogsAsync()));

app.Run();

static string GenerateJwt(ApiUser user, SymmetricSecurityKey key)
{
    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
    var claims = new[]
    {
        new Claim(JwtRegisteredClaimNames.Sub, user.Id),
        new Claim(ClaimTypes.Name, user.Username),
        new Claim(ClaimTypes.Email, user.Email),
        new Claim(ClaimTypes.Role, user.Role)
    };
    var token = new JwtSecurityToken(
        issuer: "KryvnixAntivirus.Api",
        audience: "KryvnixAntivirus.Clients",
        claims: claims,
        expires: DateTime.UtcNow.AddHours(12),
        signingCredentials: creds);
    return new JwtSecurityTokenHandler().WriteToken(token);
}

public sealed class SecurityHub : Hub { }

public record RegisterRequest(string Username, string Email, string Password, string? FullName);
public record LoginRequest(string UsernameOrEmail, string Password);
public record HeartbeatRequest(string DeviceId, string Hostname, string OsVersion, string AgentVersion, string DbVersion, bool RealtimeEnabled);
public record RemoteScanRequest(string Mode);
public record CreateSignatureRequest(string Sha256, string ThreatName, string Category, string Severity);
public record CreateYaraRequest(string RuleName, string Category, string Severity, string RuleSource);
public record DetectionReportRequest(string DeviceId, string FileName, string FilePath, string Sha256, string ThreatName, string Category, string Severity, string DetectionMethod, int HeuristicScore, string ActionTaken);

public sealed class ApiUser
{
    public string Id { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string FullName { get; set; } = string.Empty;
    public string Role { get; set; } = "Standard";
    public string PasswordHash { get; set; } = string.Empty;
}

public sealed class CentralStore
{
    private readonly string _connStr;
    private readonly Ed25519PrivateKeyParameters _edPrivate;
    private readonly Ed25519PublicKeyParameters _edPublic;

    public CentralStore(IConfiguration config)
    {
        var dbPath = config["DatabasePath"] ?? Path.Combine(AppContext.BaseDirectory, "kryvnix_central.db");
        _connStr = new SqliteConnectionStringBuilder { DataSource = dbPath, Mode = SqliteOpenMode.ReadWriteCreate }.ToString();

        var keyGen = new Ed25519KeyPairGenerator();
        keyGen.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        var kp = keyGen.GenerateKeyPair();
        _edPrivate = (Ed25519PrivateKeyParameters)kp.Private;
        _edPublic = (Ed25519PublicKeyParameters)kp.Public;
    }

    public (string SignatureBase64, string PublicKeyBase64) SignPayloadEd25519(byte[] payload)
    {
        var signer = new Ed25519Signer();
        signer.Init(true, _edPrivate);
        signer.BlockUpdate(payload, 0, payload.Length);
        return (Convert.ToBase64String(signer.GenerateSignature()), Convert.ToBase64String(_edPublic.GetEncoded()));
    }

    private async Task<SqliteConnection> OpenAsync()
    {
        var c = new SqliteConnection(_connStr);
        await c.OpenAsync();
        return c;
    }

    public async Task InitializeAsync()
    {
        await using var c = await OpenAsync();
        await using var cmd = c.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT UNIQUE, email TEXT UNIQUE, full_name TEXT, role TEXT, password_hash TEXT, created_at TEXT);
            CREATE TABLE IF NOT EXISTS devices (device_id TEXT PRIMARY KEY, hostname TEXT, os_version TEXT, agent_version TEXT, db_version TEXT, realtime_enabled INTEGER, status TEXT, last_heartbeat TEXT);
            CREATE TABLE IF NOT EXISTS signatures (id INTEGER PRIMARY KEY AUTOINCREMENT, sha256 TEXT UNIQUE, threat_name TEXT, category TEXT, severity TEXT, added_at TEXT);
            CREATE TABLE IF NOT EXISTS yara_rules (id INTEGER PRIMARY KEY AUTOINCREMENT, rule_name TEXT UNIQUE, category TEXT, severity TEXT, rule_source TEXT, enabled INTEGER, updated_at TEXT);
            CREATE TABLE IF NOT EXISTS detections (id TEXT PRIMARY KEY, device_id TEXT, file_name TEXT, file_path TEXT, sha256 TEXT, threat_name TEXT, category TEXT, severity TEXT, detection_method TEXT, heuristic_score INTEGER, action_taken TEXT, detected_at TEXT);
            CREATE TABLE IF NOT EXISTS audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT, action TEXT, details TEXT, created_at TEXT);
            CREATE TABLE IF NOT EXISTS remote_commands (id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT, command TEXT, consumed INTEGER DEFAULT 0, created_at TEXT);
            """;
        await cmd.ExecuteNonQueryAsync();

        // Seed default Admin + Fleet data if empty
        await using var check = c.CreateCommand();
        check.CommandText = "SELECT COUNT(*) FROM users;";
        if (Convert.ToInt32(await check.ExecuteScalarAsync()) == 0)
        {
            await CreateUserAsync("admin", "admin@kryvnix.io", "Security Administrator", "KryvnixAdmin@2026", "Admin");

            await UpsertDeviceHeartbeatAsync(new HeartbeatRequest("KRV-DESKTOP-MAIN", "WORKSTATION-01", "Windows 11 Pro 24H2", "2.0.0", "v2026.11.25", true));
            await UpsertDeviceHeartbeatAsync(new HeartbeatRequest("KRV-FINANCE-02", "FINANCE-PC-02", "Windows 11 Enterprise", "2.0.0", "v2026.11.25", true));
            await UpsertDeviceHeartbeatAsync(new HeartbeatRequest("KRV-LAB-03", "MALWARE-LAB-03", "Windows 10 Pro", "2.0.0", "v2025.01.15", false));

            await AddSignatureAsync(new CreateSignatureRequest("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "EICAR-Test-File", "Trojan", "High"));
            await AddSignatureAsync(new CreateSignatureRequest("ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa", "Ransom.Win32.WannaCry.Gen", "Ransomware", "Critical"));
            await AddSignatureAsync(new CreateSignatureRequest("24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c", "Ransom.Win32.LockBit.B", "Ransomware", "Critical"));

            await AddYaraRuleAsync(new CreateYaraRequest("Kryvnix_Ransomware_Note", "Ransomware", "Critical", "rule Kryvnix_Ransomware_Note { strings: $a = \"YOUR FILES HAVE BEEN ENCRYPTED\" nocase condition: $a }"));
            await AddYaraRuleAsync(new CreateYaraRequest("Kryvnix_Encoded_PowerShell", "Trojan", "High", "rule Kryvnix_Encoded_PowerShell { strings: $a = \"powershell -enc \" nocase condition: $a }"));

            await AddDetectionAsync(new DetectionReportRequest("KRV-DESKTOP-MAIN", "eicar.com", @"C:\Users\Downloads\eicar.com", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "EICAR-Test-File", "Trojan", "High", "SHA-256 Signature", 100, "Quarantined"));
            await AddDetectionAsync(new DetectionReportRequest("KRV-LAB-03", "lockbit_sim.exe", @"C:\Temp\lockbit_sim.exe", "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c", "Ransom.Win32.LockBit.B", "Ransomware", "Critical", "Offline AI PE Classifier", 94, "Quarantined"));
            await LogAuditAsync("system", "SYSTEM_INIT", "Kryvnix Central Management API v2.0.0 initialized");
        }
    }

    public async Task<ApiUser?> CreateUserAsync(string username, string email, string fullName, string password, string role)
    {
        await using var c = await OpenAsync();
        var user = new ApiUser
        {
            Id = Guid.NewGuid().ToString("N"),
            Username = username,
            Email = email.ToLowerInvariant(),
            FullName = fullName,
            Role = role,
            PasswordHash = HashPassword(password)
        };
        try
        {
            await using var cmd = c.CreateCommand();
            cmd.CommandText = "INSERT INTO users (id, username, email, full_name, role, password_hash, created_at) VALUES ($id,$u,$e,$fn,$r,$h,$dt);";
            cmd.Parameters.AddWithValue("$id", user.Id);
            cmd.Parameters.AddWithValue("$u", user.Username);
            cmd.Parameters.AddWithValue("$e", user.Email);
            cmd.Parameters.AddWithValue("$fn", user.FullName);
            cmd.Parameters.AddWithValue("$r", user.Role);
            cmd.Parameters.AddWithValue("$h", user.PasswordHash);
            cmd.Parameters.AddWithValue("$dt", DateTime.UtcNow.ToString("O"));
            await cmd.ExecuteNonQueryAsync();
            return user;
        }
        catch { return null; }
    }

    public async Task<ApiUser?> VerifyUserAsync(string identifier, string password)
    {
        await using var c = await OpenAsync();
        await using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT id, username, email, full_name, role, password_hash FROM users WHERE LOWER(username)=LOWER($x) OR LOWER(email)=LOWER($x) LIMIT 1;";
        cmd.Parameters.AddWithValue("$x", identifier.Trim());
        await using var r = await cmd.ExecuteReaderAsync();
        if (!await r.ReadAsync()) return null;
        var u = new ApiUser { Id = r.GetString(0), Username = r.GetString(1), Email = r.GetString(2), FullName = r.GetString(3), Role = r.GetString(4), PasswordHash = r.GetString(5) };
        return VerifyHash(password, u.PasswordHash) ? u : null;
    }

    public async Task<object> UpsertDeviceHeartbeatAsync(HeartbeatRequest req)
    {
        var now = DateTime.UtcNow.ToString("O");
        var status = req.RealtimeEnabled ? "Protected" : "Attention";
        await using var c = await OpenAsync();
        await using var cmd = c.CreateCommand();
        cmd.CommandText = """
            INSERT INTO devices (device_id, hostname, os_version, agent_version, db_version, realtime_enabled, status, last_heartbeat)
            VALUES ($id,$h,$os,$av,$dbv,$rt,$st,$hb)
            ON CONFLICT(device_id) DO UPDATE SET hostname=excluded.hostname, os_version=excluded.os_version, agent_version=excluded.agent_version, db_version=excluded.db_version, realtime_enabled=excluded.realtime_enabled, status=excluded.status, last_heartbeat=excluded.last_heartbeat;
            """;
        cmd.Parameters.AddWithValue("$id", req.DeviceId);
        cmd.Parameters.AddWithValue("$h", req.Hostname);
        cmd.Parameters.AddWithValue("$os", req.OsVersion);
        cmd.Parameters.AddWithValue("$av", req.AgentVersion);
        cmd.Parameters.AddWithValue("$dbv", req.DbVersion);
        cmd.Parameters.AddWithValue("$rt", req.RealtimeEnabled ? 1 : 0);
        cmd.Parameters.AddWithValue("$st", status);
        cmd.Parameters.AddWithValue("$hb", now);
        await cmd.ExecuteNonQueryAsync();
        return new { req.DeviceId, req.Hostname, req.OsVersion, req.AgentVersion, req.DbVersion, req.RealtimeEnabled, status, lastHeartbeat = now };
    }

    public async Task<List<object>> GetDevicesAsync()
    {
        await using var c = await OpenAsync();
        await using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT device_id, hostname, os_version, agent_version, db_version, realtime_enabled, status, last_heartbeat FROM devices ORDER BY last_heartbeat DESC;";
        var list = new List<object>();
        await using var r = await cmd.ExecuteReaderAsync();
        while (await r.ReadAsync())
        {
            list.Add(new { deviceId = r.GetString(0), hostname = r.GetString(1), osVersion = r.GetString(2), agentVersion = r.GetString(3), dbVersion = r.GetString(4), realtimeEnabled = r.GetInt32(5) == 1, status = r.GetString(6), lastHeartbeat = r.GetString(7) });
        }
        return list;
    }

    public async Task QueueRemoteCommandAsync(string deviceId, string command)
    {
        await using var c = await OpenAsync();
        await using var cmd = c.CreateCommand();
        cmd.CommandText = "INSERT INTO remote_commands (device_id, command, consumed, created_at) VALUES ($d,$cmd,0,$dt);";
        cmd.Parameters.AddWithValue("$d", deviceId);
        cmd.Parameters.AddWithValue("$cmd", command);
        cmd.Parameters.AddWithValue("$dt", DateTime.UtcNow.ToString("O"));
        await cmd.ExecuteNonQueryAsync();
    }

    public async Task<List<string>> ConsumePendingCommandsAsync(string deviceId)
    {
        await using var c = await OpenAsync();
        var list = new List<string>();
        await using (var cmd = c.CreateCommand())
        {
            cmd.CommandText = "SELECT command FROM remote_commands WHERE device_id=$d AND consumed=0;";
            cmd.Parameters.AddWithValue("$d", deviceId);
            await using var r = await cmd.ExecuteReaderAsync();
            while (await r.ReadAsync()) list.Add(r.GetString(0));
        }
        if (list.Count > 0)
        {
            await using var upd = c.CreateCommand();
            upd.CommandText = "UPDATE remote_commands SET consumed=1 WHERE device_id=$d AND consumed=0;";
            upd.Parameters.AddWithValue("$d", deviceId);
            await upd.ExecuteNonQueryAsync();
        }
        return list;
    }

    public async Task<List<object>> GetSignaturesAsync()
    {
        await using var c = await OpenAsync();
        await using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT id, sha256, threat_name, category, severity, added_at FROM signatures ORDER BY id DESC;";
        var list = new List<object>();
        await using var r = await cmd.ExecuteReaderAsync();
        while (await r.ReadAsync()) list.Add(new { id = r.GetInt64(0), sha256 = r.GetString(1), threatName = r.GetString(2), category = r.GetString(3), severity = r.GetString(4), addedAt = r.GetString(5) });
        return list;
    }

    public async Task<object> AddSignatureAsync(CreateSignatureRequest req)
    {
        var now = DateTime.UtcNow.ToString("O");
        await using var c = await OpenAsync();
        await using var cmd = c.CreateCommand();
        cmd.CommandText = "INSERT OR IGNORE INTO signatures (sha256, threat_name, category, severity, added_at) VALUES ($s,$n,$cat,$sev,$dt); SELECT last_insert_rowid();";
        cmd.Parameters.AddWithValue("$s", req.Sha256.Trim().ToLowerInvariant());
        cmd.Parameters.AddWithValue("$n", req.ThreatName.Trim());
        cmd.Parameters.AddWithValue("$cat", req.Category);
        cmd.Parameters.AddWithValue("$sev", req.Severity);
        cmd.Parameters.AddWithValue("$dt", now);
        var id = Convert.ToInt64(await cmd.ExecuteScalarAsync());
        return new { id, req.Sha256, req.ThreatName, req.Category, req.Severity, addedAt = now };
    }

    public async Task DeleteSignatureAsync(long id)
    {
        await using var c = await OpenAsync();
        await using var cmd = c.CreateCommand();
        cmd.CommandText = "DELETE FROM signatures WHERE id=$id;";
        cmd.Parameters.AddWithValue("$id", id);
        await cmd.ExecuteNonQueryAsync();
    }

    public async Task<List<object>> GetYaraRulesAsync()
    {
        await using var c = await OpenAsync();
        await using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT id, rule_name, category, severity, rule_source, enabled, updated_at FROM yara_rules ORDER BY id DESC;";
        var list = new List<object>();
        await using var r = await cmd.ExecuteReaderAsync();
        while (await r.ReadAsync()) list.Add(new { id = r.GetInt64(0), ruleName = r.GetString(1), category = r.GetString(2), severity = r.GetString(3), ruleSource = r.GetString(4), enabled = r.GetInt32(5) == 1, updatedAt = r.GetString(6) });
        return list;
    }

    public async Task<object> AddYaraRuleAsync(CreateYaraRequest req)
    {
        var now = DateTime.UtcNow.ToString("O");
        await using var c = await OpenAsync();
        await using var cmd = c.CreateCommand();
        cmd.CommandText = "INSERT OR REPLACE INTO yara_rules (rule_name, category, severity, rule_source, enabled, updated_at) VALUES ($n,$cat,$sev,$src,1,$dt); SELECT last_insert_rowid();";
        cmd.Parameters.AddWithValue("$n", req.RuleName.Trim());
        cmd.Parameters.AddWithValue("$cat", req.Category);
        cmd.Parameters.AddWithValue("$sev", req.Severity);
        cmd.Parameters.AddWithValue("$src", req.RuleSource);
        cmd.Parameters.AddWithValue("$dt", now);
        var id = Convert.ToInt64(await cmd.ExecuteScalarAsync());
        return new { id, req.RuleName, req.Category, req.Severity, req.RuleSource, enabled = true, updatedAt = now };
    }

    public async Task ToggleYaraRuleAsync(long id)
    {
        await using var c = await OpenAsync();
        await using var cmd = c.CreateCommand();
        cmd.CommandText = "UPDATE yara_rules SET enabled = CASE WHEN enabled=1 THEN 0 ELSE 1 END WHERE id=$id;";
        cmd.Parameters.AddWithValue("$id", id);
        await cmd.ExecuteNonQueryAsync();
    }

    public async Task DeleteYaraRuleAsync(long id)
    {
        await using var c = await OpenAsync();
        await using var cmd = c.CreateCommand();
        cmd.CommandText = "DELETE FROM yara_rules WHERE id=$id;";
        cmd.Parameters.AddWithValue("$id", id);
        await cmd.ExecuteNonQueryAsync();
    }

    public async Task<object> AddDetectionAsync(DetectionReportRequest req)
    {
        var id = Guid.NewGuid().ToString("N");
        var now = DateTime.UtcNow.ToString("O");
        await using var c = await OpenAsync();
        await using var cmd = c.CreateCommand();
        cmd.CommandText = "INSERT INTO detections (id, device_id, file_name, file_path, sha256, threat_name, category, severity, detection_method, heuristic_score, action_taken, detected_at) VALUES ($id,$d,$fn,$fp,$sha,$tn,$cat,$sev,$m,$hs,$act,$dt);";
        cmd.Parameters.AddWithValue("$id", id);
        cmd.Parameters.AddWithValue("$d", req.DeviceId);
        cmd.Parameters.AddWithValue("$fn", req.FileName);
        cmd.Parameters.AddWithValue("$fp", req.FilePath);
        cmd.Parameters.AddWithValue("$sha", req.Sha256);
        cmd.Parameters.AddWithValue("$tn", req.ThreatName);
        cmd.Parameters.AddWithValue("$cat", req.Category);
        cmd.Parameters.AddWithValue("$sev", req.Severity);
        cmd.Parameters.AddWithValue("$m", req.DetectionMethod);
        cmd.Parameters.AddWithValue("$hs", req.HeuristicScore);
        cmd.Parameters.AddWithValue("$act", req.ActionTaken);
        cmd.Parameters.AddWithValue("$dt", now);
        await cmd.ExecuteNonQueryAsync();
        return new { id, req.DeviceId, req.FileName, req.ThreatName, req.Category, req.Severity, req.DetectionMethod, req.ActionTaken, detectedAt = now };
    }

    public async Task<List<object>> GetDetectionsAsync()
    {
        await using var c = await OpenAsync();
        await using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT id, device_id, file_name, file_path, sha256, threat_name, category, severity, detection_method, heuristic_score, action_taken, detected_at FROM detections ORDER BY detected_at DESC LIMIT 100;";
        var list = new List<object>();
        await using var r = await cmd.ExecuteReaderAsync();
        while (await r.ReadAsync()) list.Add(new { id = r.GetString(0), deviceId = r.GetString(1), fileName = r.GetString(2), filePath = r.GetString(3), sha256 = r.GetString(4), threatName = r.GetString(5), category = r.GetString(6), severity = r.GetString(7), detectionMethod = r.GetString(8), heuristicScore = r.GetInt32(9), actionTaken = r.GetString(10), detectedAt = r.GetString(11) });
        return list;
    }

    public async Task LogAuditAsync(string actor, string action, string details)
    {
        await using var c = await OpenAsync();
        await using var cmd = c.CreateCommand();
        cmd.CommandText = "INSERT INTO audit_logs (actor, action, details, created_at) VALUES ($a,$act,$det,$dt);";
        cmd.Parameters.AddWithValue("$a", actor);
        cmd.Parameters.AddWithValue("$act", action);
        cmd.Parameters.AddWithValue("$det", details);
        cmd.Parameters.AddWithValue("$dt", DateTime.UtcNow.ToString("O"));
        await cmd.ExecuteNonQueryAsync();
    }

    public async Task<List<object>> GetAuditLogsAsync()
    {
        await using var c = await OpenAsync();
        await using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT id, actor, action, details, created_at FROM audit_logs ORDER BY id DESC LIMIT 100;";
        var list = new List<object>();
        await using var r = await cmd.ExecuteReaderAsync();
        while (await r.ReadAsync()) list.Add(new { id = r.GetInt64(0), actor = r.GetString(1), action = r.GetString(2), details = r.GetString(3), createdAt = r.GetString(4) });
        return list;
    }

    public async Task<object> GetFleetSummaryAsync()
    {
        var devices = await GetDevicesAsync();
        var sigs = await GetSignaturesAsync();
        var yara = await GetYaraRulesAsync();
        var detections = await GetDetectionsAsync();
        var audits = await GetAuditLogsAsync();
        return new
        {
            totalEndpoints = devices.Count,
            totalSignatures = sigs.Count,
            totalYaraRules = yara.Count,
            totalDetections = detections.Count,
            latestDbVersion = $"v{DateTime.UtcNow:yyyy.MM.dd}",
            recentAudit = audits.Take(10)
        };
    }

    private static string HashPassword(string pwd)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var hash = Rfc2898DeriveBytes.Pbkdf2(pwd, salt, 120_000, HashAlgorithmName.SHA256, 32);
        return $"PBKDF2-SHA256$120000${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    private static bool VerifyHash(string pwd, string stored)
    {
        var p = stored.Split('$');
        if (p.Length != 4) return false;
        var salt = Convert.FromBase64String(p[2]);
        var expected = Convert.FromBase64String(p[3]);
        var actual = Rfc2898DeriveBytes.Pbkdf2(pwd, salt, int.Parse(p[1]), HashAlgorithmName.SHA256, expected.Length);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }
}
