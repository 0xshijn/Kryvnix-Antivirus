using System.IO;
using System.Text;
using KryvnixAntivirus.Desktop.Data;
using KryvnixAntivirus.Desktop.Models;
using KryvnixAntivirus.Desktop.Services;
using Xunit;

namespace KryvnixAntivirus.Tests;

public sealed class CoreEngineAndUiTests : IDisposable
{
    private readonly string _tempRoot;
    private readonly LocalDatabaseService _db;

    public CoreEngineAndUiTests()
    {
        _tempRoot = Path.Combine(Path.GetTempPath(), "KryvnixTests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempRoot);
        _db = new LocalDatabaseService(Path.Combine(_tempRoot, "test.db"));
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_tempRoot)) Directory.Delete(_tempRoot, recursive: true);
        }
        catch
        {
            // Ignore locked temp cleanup
        }
    }

    [Fact]
    public async Task EicarTestPayload_IsDetectedBySha256AndEicarEngine()
    {
        await _db.InitializeAsync();
        var analyzer = new LocalThreatAnalyzer(_db);

        // Use in-memory analysis so host Windows Defender does not delete the test file mid-test
        const string eicar = @"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-" + @"STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        var eicarBytes = Encoding.ASCII.GetBytes(eicar);

        var result = await analyzer.AnalyzeBytesAsync("eicar.com", @"C:\Test\eicar.com", eicarBytes, heuristicThreshold: 65);

        Assert.NotNull(result);
        Assert.Equal("EICAR-Test-File", result!.ThreatName);
        Assert.Equal(ThreatCategory.Trojan, result.Category);
        Assert.Equal("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", result.Sha256);
    }

    [Fact]
    public async Task DiskScan_DetectsYaraThreatSampleOnDisk()
    {
        await _db.InitializeAsync();
        var analyzer = new LocalThreatAnalyzer(_db);

        var samplePath = Path.Combine(_tempRoot, "kryvnix_sample.bin");
        await File.WriteAllTextAsync(samplePath, "KRYVNIX-SIMULATED-THREAT-MARKER", Encoding.ASCII);

        var result = await analyzer.AnalyzeFileAsync(samplePath, heuristicThreshold: 65, maxFileSizeBytes: 10 * 1024 * 1024);

        Assert.NotNull(result);
        Assert.Equal("YARA.Kryvnix.TestTrojan", result!.ThreatName);
        Assert.Equal("YARA Rule", result.DetectionMethod);
    }

    [Fact]
    public async Task BenignTextFile_DoesNotTriggerFalsePositive()
    {
        await _db.InitializeAsync();
        var analyzer = new LocalThreatAnalyzer(_db);

        var safePath = Path.Combine(_tempRoot, "notes.txt");
        await File.WriteAllTextAsync(safePath, "Hello Kryvnix Antivirus — normal clean document.");

        var result = await analyzer.AnalyzeFileAsync(safePath, heuristicThreshold: 65, maxFileSizeBytes: 10 * 1024 * 1024);

        Assert.Null(result);
    }

    [Fact]
    public async Task SyntheticSuspiciousPe_TriggersPeHeuristicAndEntropyScoring()
    {
        await _db.InitializeAsync();
        var analyzer = new LocalThreatAnalyzer(_db);

        // Build minimal valid PE header with UPX section, RWX flags, and suspicious injection API strings
        var buffer = new byte[2048];
        buffer[0] = (byte)'M';
        buffer[1] = (byte)'Z';
        BitConverter.TryWriteBytes(buffer.AsSpan(0x3C, 4), 0x80);

        // PE\0\0 at 0x80
        buffer[0x80] = (byte)'P';
        buffer[0x81] = (byte)'E';
        BitConverter.TryWriteBytes(buffer.AsSpan(0x86, 2), (ushort)1); // NumberOfSections = 1
        BitConverter.TryWriteBytes(buffer.AsSpan(0x94, 2), (ushort)0xE0); // OptionalHeaderSize

        int secOffset = 0x80 + 24 + 0xE0;
        Encoding.ASCII.GetBytes("UPX0\0\0\0\0").CopyTo(buffer, secOffset);
        BitConverter.TryWriteBytes(buffer.AsSpan(secOffset + 36, 4), 0xE0000020u); // RWX section

        var apis = Encoding.ASCII.GetBytes("VirtualAllocEx\0WriteProcessMemory\0CreateRemoteThread\0NtUnmapViewOfSection\0");
        apis.CopyTo(buffer, secOffset + 64);

        var (isPe, score, _, indicators) = analyzer.AnalyzePeAndHeuristics(buffer);

        Assert.True(isPe);
        Assert.True(score >= 65, $"Expected heuristic score >= 65, got {score}");
        Assert.Contains("Packer:UPX0", indicators);
        Assert.Contains("VirtualAllocEx", indicators);
    }

    [Fact]
    public async Task Aes256GcmQuarantine_EncryptsRestoresAndDeletesCleanly()
    {
        await _db.InitializeAsync();
        var vaultDir = Path.Combine(_tempRoot, "vault");
        var quarantine = new EncryptedQuarantineService(_db, vaultDir);

        var originalPath = Path.Combine(_tempRoot, "suspicious_sample.bin");
        var originalPayload = Encoding.UTF8.GetBytes("KRYVNIX-QUARANTINE-ROUNDTRIP-PAYLOAD-1234567890");
        await File.WriteAllBytesAsync(originalPath, originalPayload);

        var detection = new DetectionItem
        {
            FileName = "suspicious_sample.bin",
            FilePath = originalPath,
            Sha256 = "abcdef",
            ThreatName = "Trojan.Test.Roundtrip",
            Category = ThreatCategory.Trojan,
            Severity = ThreatSeverity.High,
            FileSize = originalPayload.Length
        };
        await _db.RecordDetectionAsync(detection);

        // 1. Quarantine (encrypt & remove original)
        var qItem = await quarantine.QuarantineFileAsync(detection);
        Assert.False(File.Exists(originalPath));
        Assert.True(File.Exists(qItem.VaultFilePath));

        var vaultBytes = await File.ReadAllBytesAsync(qItem.VaultFilePath);
        Assert.NotEqual(originalPayload, vaultBytes); // Must be encrypted

        // 2. Restore (decrypt & verify exact bytes)
        var restoredPath = await quarantine.RestoreFileAsync(qItem);
        Assert.True(File.Exists(restoredPath));
        Assert.False(File.Exists(qItem.VaultFilePath));
        var restoredBytes = await File.ReadAllBytesAsync(restoredPath);
        Assert.Equal(originalPayload, restoredBytes);
    }

    [Fact]
    public async Task Ed25519SignatureUpdate_VerifiesAndCommitsAtomicSqliteTransaction()
    {
        await _db.InitializeAsync();
        var updater = new SignatureUpdateService(_db);
        var beforeCount = await _db.GetTotalSignatureCountAsync();

        var result = await updater.CheckAndApplyUpdatesAsync();

        Assert.True(result.Success);
        Assert.True(result.Ed25519Verified);
        Assert.True(result.TotalSignatures > beforeCount);

        var history = await _db.GetUpdateHistoryAsync();
        Assert.Contains(history, h => h.Version == result.NewVersion && h.VerifiedEd25519);
    }

    [Fact]
    public void ProtectionStateEvaluation_ReflectsAllFiveRequiredStates()
    {
        var ipc = new NamedPipeEngineClient();
        var analyzer = new LocalThreatAnalyzer(_db);
        var quarantine = new EncryptedQuarantineService(_db, Path.Combine(_tempRoot, "v2"));
        var scanner = new HybridScanEngineService(_db, analyzer, ipc);
        using var realtime = new RealtimeProtectionService(_db, analyzer, quarantine, scanner);
        using var tray = new SystemTrayService();
        var stateSvc = new AppStateService(_db, ipc, realtime, tray);

        var operational = new EngineStatusSnapshot { IsEngineOperational = true };
        var offline = new EngineStatusSnapshot { IsEngineOperational = false };
        var allOn = new RealtimeProtectionState();
        var partialOff = new RealtimeProtectionState { IsMasterEnabled = true, NetworkShieldEnabled = false };
        var masterOff = new RealtimeProtectionState { IsMasterEnabled = false };
        var settings = new AppSettings();

        Assert.Equal(ProtectionState.ServiceUnavailable, stateSvc.EvaluateProtectionState(offline, allOn, 0, settings));
        Assert.Equal(ProtectionState.ThreatDetected, stateSvc.EvaluateProtectionState(operational, allOn, 2, settings));
        Assert.Equal(ProtectionState.ProtectionDisabled, stateSvc.EvaluateProtectionState(operational, masterOff, 0, settings));
        Assert.Equal(ProtectionState.AttentionRequired, stateSvc.EvaluateProtectionState(operational, partialOff, 0, settings));
        Assert.Equal(ProtectionState.Protected, stateSvc.EvaluateProtectionState(operational, allOn, 0, settings));
    }

    [Fact]
    public async Task DashboardStats_CalculatesPercentagesAccuratelyFromSqliteData()
    {
        await _db.InitializeAsync();
        var stats = await _db.GetDashboardStatsAsync(TimeRangeFilter.Last7Days);

        Assert.True(stats.TotalFilesScanned > 0);
        Assert.Equal(246, stats.ThreatsDetected);
        Assert.Equal(7, stats.ThreatBreakdown.Count);
        Assert.Equal(246, stats.ThreatBreakdown.Sum(x => x.Count));

        var trojan = stats.ThreatBreakdown.Single(x => x.Category == ThreatCategory.Trojan);
        Assert.Equal(90, trojan.Count);
        Assert.Equal(36.6, trojan.Percentage);
    }
}
