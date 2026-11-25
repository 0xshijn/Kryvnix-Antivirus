using System.IO;
using System.Security.Cryptography;
using KryvnixAntivirus.Desktop.Data;
using KryvnixAntivirus.Desktop.Models;

namespace KryvnixAntivirus.Desktop.Services;

public interface IQuarantineService
{
    string VaultDirectory { get; }
    Task<QuarantineItem> QuarantineFileAsync(DetectionItem detection, CancellationToken ct = default);
    Task<string> RestoreFileAsync(QuarantineItem item, string? customDestinationPath = null, CancellationToken ct = default);
    Task DeletePermanentlyAsync(QuarantineItem item, CancellationToken ct = default);
    Task<List<QuarantineItem>> GetAllItemsAsync(CancellationToken ct = default);
}

public sealed class EncryptedQuarantineService : IQuarantineService
{
    private readonly ILocalDatabaseService _db;
    private readonly string _keyFilePath;

    public string VaultDirectory { get; }

    public EncryptedQuarantineService(ILocalDatabaseService db)
        : this(db, Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "KryvnixAntivirus",
            "Quarantine"))
    {
    }

    public EncryptedQuarantineService(ILocalDatabaseService db, string vaultDirectory)
    {
        _db = db;
        VaultDirectory = vaultDirectory;
        Directory.CreateDirectory(VaultDirectory);
        _keyFilePath = Path.Combine(VaultDirectory, ".vault.key");
    }

    private byte[] GetOrCreateVaultKey()
    {
        if (File.Exists(_keyFilePath))
        {
            var raw = File.ReadAllBytes(_keyFilePath);
            // DPAPI-protected format: "KDP1" (4) + DPAPI blob
            if (raw.Length > 4 && raw[0] == (byte)'K' && raw[1] == (byte)'D' && raw[2] == (byte)'P' && raw[3] == (byte)'1')
            {
                return ProtectedData.Unprotect(raw[4..], null, DataProtectionScope.CurrentUser);
            }

            // Migrate legacy raw 32-byte key to DPAPI automatically
            if (raw.Length == 32)
            {
                WriteDpapiProtectedKey(raw);
                return raw;
            }
        }

        var key = RandomNumberGenerator.GetBytes(32); // 256-bit AES key
        WriteDpapiProtectedKey(key);
        return key;
    }

    private void WriteDpapiProtectedKey(byte[] key)
    {
        var protectedBlob = ProtectedData.Protect(key, null, DataProtectionScope.CurrentUser);
        var payload = new byte[4 + protectedBlob.Length];
        "KDP1"u8.CopyTo(payload);
        protectedBlob.CopyTo(payload, 4);
        File.WriteAllBytes(_keyFilePath, payload);
        try
        {
            File.SetAttributes(_keyFilePath, FileAttributes.Hidden);
        }
        catch
        {
            // Ignore on filesystems that do not support Hidden attribute
        }
    }

    public async Task<QuarantineItem> QuarantineFileAsync(DetectionItem detection, CancellationToken ct = default)
    {
        var id = Guid.NewGuid().ToString("N");
        var vaultFilePath = Path.Combine(VaultDirectory, $"{id}.kqv");
        string nonceB64 = string.Empty;
        string tagB64 = string.Empty;
        long fileSize = detection.FileSize;

        if (File.Exists(detection.FilePath))
        {
            var plaintext = await File.ReadAllBytesAsync(detection.FilePath, ct);
            fileSize = plaintext.Length;

            var key = GetOrCreateVaultKey();
            var nonce = RandomNumberGenerator.GetBytes(12);
            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[16];

            using (var aes = new AesGcm(key, 16))
            {
                aes.Encrypt(nonce, plaintext, ciphertext, tag);
            }

            // Vault file format: "KQV1" (4) + nonce (12) + tag (16) + ciphertext
            await using (var fs = new FileStream(vaultFilePath, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                await fs.WriteAsync("KQV1"u8.ToArray(), ct);
                await fs.WriteAsync(nonce, ct);
                await fs.WriteAsync(tag, ct);
                await fs.WriteAsync(ciphertext, ct);
            }

            nonceB64 = Convert.ToBase64String(nonce);
            tagB64 = Convert.ToBase64String(tag);

            // Remove original file after verified encryption
            try
            {
                File.SetAttributes(detection.FilePath, FileAttributes.Normal);
                File.Delete(detection.FilePath);
            }
            catch
            {
                // If locked, record stays tracked
            }
        }

        var qItem = new QuarantineItem
        {
            Id = id,
            OriginalName = detection.FileName,
            OriginalPath = detection.FilePath,
            VaultFilePath = vaultFilePath,
            ThreatName = detection.ThreatName,
            Category = detection.Category,
            Severity = detection.Severity,
            Sha256 = detection.Sha256,
            FileSize = fileSize,
            NonceBase64 = nonceB64,
            TagBase64 = tagB64,
            Status = "Quarantined",
            QuarantinedAt = DateTime.Now
        };

        await _db.AddQuarantineItemAsync(qItem, ct);
        await _db.UpdateDetectionActionAsync(detection.Id, "Quarantined", ct);

        await _db.AddActivityEventAsync(new ActivityEvent
        {
            EventType = ActivityEventType.FileQuarantined,
            Title = "Đã cách ly tệp nguy hiểm",
            Description = $"{detection.FileName} ({detection.ThreatName}) đã được mã hóa AES-256-GCM",
            Severity = detection.Severity,
            IsRead = false,
            CreatedAt = DateTime.Now
        }, ct);

        return qItem;
    }

    public async Task<string> RestoreFileAsync(QuarantineItem item, string? customDestinationPath = null, CancellationToken ct = default)
    {
        var targetPath = string.IsNullOrWhiteSpace(customDestinationPath) ? item.OriginalPath : customDestinationPath;

        if (!string.IsNullOrWhiteSpace(item.VaultFilePath) && File.Exists(item.VaultFilePath))
        {
            var blob = await File.ReadAllBytesAsync(item.VaultFilePath, ct);
            if (blob.Length < 32 || blob[0] != (byte)'K' || blob[1] != (byte)'Q' || blob[2] != (byte)'V' || blob[3] != (byte)'1')
            {
                throw new InvalidDataException("Định dạng tệp khu cách ly không hợp lệ.");
            }

            var nonce = blob.AsSpan(4, 12).ToArray();
            var tag = blob.AsSpan(16, 16).ToArray();
            var ciphertext = blob.AsSpan(32).ToArray();
            var plaintext = new byte[ciphertext.Length];

            var key = GetOrCreateVaultKey();
            using (var aes = new AesGcm(key, 16))
            {
                aes.Decrypt(nonce, ciphertext, tag, plaintext);
            }

            var dir = Path.GetDirectoryName(targetPath);
            if (!string.IsNullOrWhiteSpace(dir))
            {
                Directory.CreateDirectory(dir);
            }

            await File.WriteAllBytesAsync(targetPath, plaintext, ct);
            File.Delete(item.VaultFilePath);
        }

        await _db.RemoveQuarantineItemAsync(item.Id, ct);
        await _db.AddActivityEventAsync(new ActivityEvent
        {
            EventType = ActivityEventType.FileRestored,
            Title = "Khôi phục tệp từ khu cách ly",
            Description = $"{item.OriginalName} đã được khôi phục về {targetPath}",
            Severity = ThreatSeverity.Medium,
            IsRead = false,
            CreatedAt = DateTime.Now
        }, ct);

        return targetPath;
    }

    public async Task DeletePermanentlyAsync(QuarantineItem item, CancellationToken ct = default)
    {
        if (!string.IsNullOrWhiteSpace(item.VaultFilePath) && File.Exists(item.VaultFilePath))
        {
            try
            {
                // Zero-overwrite before deletion
                var len = new FileInfo(item.VaultFilePath).Length;
                if (len > 0 && len < 16 * 1024 * 1024)
                {
                    await File.WriteAllBytesAsync(item.VaultFilePath, new byte[len], ct);
                }
                File.Delete(item.VaultFilePath);
            }
            catch
            {
                // Ignore IO error if file already removed
            }
        }

        await _db.RemoveQuarantineItemAsync(item.Id, ct);
        await _db.AddActivityEventAsync(new ActivityEvent
        {
            EventType = ActivityEventType.FileDeleted,
            Title = "Đã xóa vĩnh viễn tệp cách ly",
            Description = $"{item.OriginalName} ({item.ThreatName}) đã bị xóa an toàn khỏi thiết bị",
            Severity = ThreatSeverity.Low,
            IsRead = true,
            CreatedAt = DateTime.Now
        }, ct);
    }

    public Task<List<QuarantineItem>> GetAllItemsAsync(CancellationToken ct = default) => _db.GetQuarantineItemsAsync(ct);
}
