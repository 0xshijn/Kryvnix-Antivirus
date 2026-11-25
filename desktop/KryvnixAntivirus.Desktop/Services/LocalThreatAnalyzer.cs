using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using KryvnixAntivirus.Desktop.Data;
using KryvnixAntivirus.Desktop.Models;

namespace KryvnixAntivirus.Desktop.Services;

public interface ILocalThreatAnalyzer
{
    Task<DetectionItem?> AnalyzeFileAsync(string filePath, int heuristicThreshold, long maxFileSizeBytes, CancellationToken ct = default);
    Task<DetectionItem?> AnalyzeBytesAsync(string fileName, string filePath, byte[] fileBytes, int heuristicThreshold, CancellationToken ct = default);
    Task<string> ComputeSha256Async(string filePath, CancellationToken ct = default);
    double CalculateShannonEntropy(ReadOnlySpan<byte> data);
    (bool IsPe, int HeuristicScore, double MaxSectionEntropy, List<string> MatchedIndicators) AnalyzePeAndHeuristics(ReadOnlySpan<byte> data);
}

public sealed class LocalThreatAnalyzer : ILocalThreatAnalyzer
{
    private readonly ILocalDatabaseService _db;
    private readonly IAuthenticodeVerifier _authenticode;
    private readonly IPeMlClassifierService _mlClassifier;

    private const int MaxArchiveEntries = 100;
    private const long MaxArchiveEntryBytes = 25 * 1024 * 1024;
    private const double MaxSafeCompressionRatio = 100.0;

    // Official harmless EICAR antivirus test pattern
    private const string EicarSignature = @"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    private static readonly (string RuleName, string Marker, ThreatCategory Category, ThreatSeverity Severity)[] YaraStyleRules =
    [
        ("YARA.Ransomware.NotePattern", "YOUR FILES HAVE BEEN ENCRYPTED", ThreatCategory.Ransomware, ThreatSeverity.Critical),
        ("YARA.Trojan.EncodedPowershell", "powershell -enc ", ThreatCategory.Trojan, ThreatSeverity.High),
        ("YARA.Backdoor.ReverseShell", "/bin/sh -i >& /dev/tcp/", ThreatCategory.Backdoor, ThreatSeverity.Critical),
        ("YARA.Spyware.CredDumper", "sekurlsa::logonpasswords", ThreatCategory.Spyware, ThreatSeverity.Critical),
        ("YARA.Kryvnix.TestTrojan", "KRYVNIX-SIMULATED-THREAT-MARKER", ThreatCategory.Trojan, ThreatSeverity.High)
    ];

    private static readonly (string ApiName, int Weight)[] SuspiciousWin32Imports =
    [
        ("VirtualAllocEx", 18),
        ("WriteProcessMemory", 20),
        ("CreateRemoteThread", 22),
        ("NtUnmapViewOfSection", 24),
        ("SetWindowsHookEx", 16),
        ("GetAsyncKeyState", 14),
        ("CryptEncrypt", 14),
        ("IsDebuggerPresent", 10),
        ("URLDownloadToFile", 16),
        ("AdjustTokenPrivileges", 12),
        ("OpenProcessToken", 10)
    ];

    public LocalThreatAnalyzer(
        ILocalDatabaseService db,
        IAuthenticodeVerifier? authenticode = null,
        IPeMlClassifierService? mlClassifier = null)
    {
        _db = db;
        _authenticode = authenticode ?? new AuthenticodeVerifier();
        _mlClassifier = mlClassifier ?? new PeMlClassifierService();
    }

    public async Task<string> ComputeSha256Async(string filePath, CancellationToken ct = default)
    {
        await using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 65536, useAsync: true);
        var hashBytes = await SHA256.HashDataAsync(stream, ct);
        return Convert.ToHexString(hashBytes).ToLowerInvariant();
    }

    public async Task<DetectionItem?> AnalyzeBytesAsync(string fileName, string filePath, byte[] fileBytes, int heuristicThreshold, CancellationToken ct = default)
    {
        if (fileBytes.Length == 0) return null;

        var sha256 = Convert.ToHexString(SHA256.HashData(fileBytes)).ToLowerInvariant();
        var sig = await _db.FindSignatureBySha256Async(sha256, ct);
        if (sig is not null)
        {
            return new DetectionItem
            {
                FileName = fileName,
                FilePath = filePath,
                Sha256 = sha256,
                ThreatName = sig.ThreatName,
                Category = sig.Category,
                Severity = sig.Severity,
                DetectionMethod = "SHA-256 Signature",
                HeuristicScore = 100,
                Entropy = CalculateShannonEntropy(fileBytes),
                FileSize = fileBytes.Length,
                ActionTaken = "Detected",
                DetectedAt = DateTime.Now
            };
        }

        var sampleLength = Math.Min(fileBytes.Length, 512 * 1024);
        var sampleBytes = fileBytes.Length == sampleLength ? fileBytes : fileBytes[..sampleLength];
        return InspectSampleBytes(fileName, filePath, sha256, fileBytes.Length, sampleBytes, heuristicThreshold);
    }

    public async Task<DetectionItem?> AnalyzeFileAsync(string filePath, int heuristicThreshold, long maxFileSizeBytes, CancellationToken ct = default)
    {
        FileInfo fi;
        try
        {
            fi = new FileInfo(filePath);
            if (!fi.Exists || fi.Length == 0 || fi.Length > maxFileSizeBytes)
            {
                return null;
            }
        }
        catch
        {
            return null;
        }

        string sha256;
        byte[] sampleBytes;
        try
        {
            sha256 = await ComputeSha256Async(filePath, ct);

            // 1. Exact SHA-256 signature match in SQLite database
            var sig = await _db.FindSignatureBySha256Async(sha256, ct);
            if (sig is not null)
            {
                return new DetectionItem
                {
                    FileName = fi.Name,
                    FilePath = filePath,
                    Sha256 = sha256,
                    ThreatName = sig.ThreatName,
                    Category = sig.Category,
                    Severity = sig.Severity,
                    DetectionMethod = "SHA-256 Signature",
                    HeuristicScore = 100,
                    FileSize = fi.Length,
                    ActionTaken = "Detected",
                    DetectedAt = DateTime.Now
                };
            }

            // Read up to first 512 KB for EICAR, YARA-style pattern, and PE/Heuristic inspection
            var readLength = (int)Math.Min(fi.Length, 512 * 1024);
            sampleBytes = new byte[readLength];
            await using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 32768, useAsync: true);
            var read = await fs.ReadAsync(sampleBytes.AsMemory(0, readLength), ct);
            if (read < readLength)
            {
                Array.Resize(ref sampleBytes, read);
            }
        }
        catch
        {
            return null;
        }

        var ext = fi.Extension.ToLowerInvariant();
        if (ext is ".zip" or ".docm" or ".xlsm" or ".pptm" or ".jar" or ".nupkg")
        {
            var archiveHit = await ScanZipArchiveSafeAsync(filePath, fi.Name, sha256, fi.Length, heuristicThreshold, ct);
            if (archiveHit is not null) return archiveHit;
        }

        bool isSigned = false;
        string signerName = string.Empty;
        if (ext is ".exe" or ".dll" or ".scr" or ".sys")
        {
            var auth = _authenticode.VerifyFile(filePath);
            isSigned = auth.IsValidSignature;
            signerName = auth.SignerName;
        }

        return InspectSampleBytes(fi.Name, filePath, sha256, fi.Length, sampleBytes, heuristicThreshold, isSigned, signerName);
    }

    private async Task<DetectionItem?> ScanZipArchiveSafeAsync(
        string archivePath,
        string archiveName,
        string archiveSha256,
        long archiveSize,
        int heuristicThreshold,
        CancellationToken ct)
    {
        try
        {
            await using var fs = new FileStream(archivePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 32768, useAsync: true);
            using var archive = new ZipArchive(fs, ZipArchiveMode.Read, leaveOpen: false);

            int count = 0;
            foreach (var entry in archive.Entries)
            {
                ct.ThrowIfCancellationRequested();
                if (++count > MaxArchiveEntries) break;
                if (entry.Length == 0) continue;

                // Anti-Zip-Bomb compression ratio guard
                if (entry.CompressedLength > 0 && entry.Length > 5 * 1024 * 1024)
                {
                    double ratio = (double)entry.Length / entry.CompressedLength;
                    if (ratio >= MaxSafeCompressionRatio)
                    {
                        return new DetectionItem
                        {
                            FileName = archiveName,
                            FilePath = archivePath,
                            Sha256 = archiveSha256,
                            ThreatName = $"Archive.ZipBomb.Suspicious (Ratio {ratio:0}:1)",
                            Category = ThreatCategory.Other,
                            Severity = ThreatSeverity.High,
                            DetectionMethod = "Archive Deep Scan",
                            HeuristicScore = 90,
                            FileSize = archiveSize,
                            ActionTaken = "Detected",
                            DetectedAt = DateTime.Now
                        };
                    }
                }

                if (entry.Length > MaxArchiveEntryBytes) continue;

                await using var entryStream = entry.Open();
                using var ms = new MemoryStream((int)Math.Min(entry.Length, 512 * 1024));
                var buffer = new byte[16384];
                int totalRead = 0;
                int n;
                while (totalRead < 512 * 1024 && (n = await entryStream.ReadAsync(buffer.AsMemory(0, Math.Min(buffer.Length, 512 * 1024 - totalRead)), ct)) > 0)
                {
                    ms.Write(buffer, 0, n);
                    totalRead += n;
                }

                var innerHit = await AnalyzeBytesAsync(entry.Name, $"{archivePath}::{entry.FullName}", ms.ToArray(), heuristicThreshold, ct);
                if (innerHit is not null)
                {
                    innerHit.FileName = $"{archiveName} -> {entry.Name}";
                    innerHit.FilePath = archivePath;
                    innerHit.DetectionMethod = $"Archive ({innerHit.DetectionMethod})";
                    return innerHit;
                }
            }
        }
        catch
        {
            // Corrupt/encrypted zip ignored cleanly
        }

        return null;
    }

    private DetectionItem? InspectSampleBytes(
        string fileName,
        string filePath,
        string sha256,
        long fileSize,
        byte[] sampleBytes,
        int heuristicThreshold,
        bool isSigned = false,
        string signerName = "")
    {
        // 2. EICAR standard test file check (even with trailing whitespace or comments)
        var asciiText = Encoding.ASCII.GetString(sampleBytes);
        if (asciiText.Contains(EicarSignature, StringComparison.Ordinal))
        {
            return new DetectionItem
            {
                FileName = fileName,
                FilePath = filePath,
                Sha256 = sha256,
                ThreatName = "EICAR-Test-File",
                Category = ThreatCategory.Trojan,
                Severity = ThreatSeverity.High,
                DetectionMethod = "EICAR Signature",
                HeuristicScore = 100,
                Entropy = CalculateShannonEntropy(sampleBytes),
                FileSize = fileSize,
                ActionTaken = "Detected",
                DetectedAt = DateTime.Now
            };
        }

        // 3. YARA-style behavioral pattern rules
        var ext = Path.GetExtension(fileName).ToLowerInvariant();
        if (ext is ".txt" or ".ps1" or ".bat" or ".cmd" or ".vbs" or ".js" or ".com" or ".exe" or ".dll" or ".scr" or ".bin")
        {
            foreach (var rule in YaraStyleRules)
            {
                if (asciiText.Contains(rule.Marker, StringComparison.OrdinalIgnoreCase))
                {
                    return new DetectionItem
                    {
                        FileName = fileName,
                        FilePath = filePath,
                        Sha256 = sha256,
                        ThreatName = rule.RuleName,
                        Category = rule.Category,
                        Severity = rule.Severity,
                        DetectionMethod = "YARA Rule",
                        HeuristicScore = 92,
                        Entropy = CalculateShannonEntropy(sampleBytes),
                        FileSize = fileSize,
                        ActionTaken = "Detected",
                        DetectedAt = DateTime.Now
                    };
                }
            }
        }

        // 4. PE Parser + Entropy + Import Heuristic + Offline AI ML PE Classifier
        if (ext is ".exe" or ".dll" or ".scr" or ".sys" && sampleBytes.Length >= 256)
        {
            var (isPe, score, maxEntropy, indicators) = AnalyzePeAndHeuristics(sampleBytes);
            var ml = _mlClassifier.ClassifyPe(sampleBytes, isSigned);

            // Valid Windows Authenticode signatures greatly reduce false-positive heuristic triggers
            int effectiveScore = isSigned ? Math.Max(0, score - 40) : score;

            if (isPe && (effectiveScore >= heuristicThreshold || (ml.IsMalicious && !isSigned)))
            {
                var cat = indicators.Any(i => i.Contains("Crypt", StringComparison.OrdinalIgnoreCase))
                    ? ThreatCategory.Ransomware
                    : indicators.Any(i => i.Contains("Hook", StringComparison.OrdinalIgnoreCase) || i.Contains("KeyState", StringComparison.OrdinalIgnoreCase))
                        ? ThreatCategory.Spyware
                        : ThreatCategory.Trojan;

                bool triggeredByAi = effectiveScore < heuristicThreshold && ml.IsMalicious;
                return new DetectionItem
                {
                    FileName = fileName,
                    FilePath = filePath,
                    Sha256 = sha256,
                    ThreatName = triggeredByAi
                        ? $"AI.Malware.PE.{cat} ({ml.ConfidencePercent:0.0}%)"
                        : $"Heuristic.PE.{cat}.Gen (Score:{effectiveScore})",
                    Category = cat,
                    Severity = (effectiveScore >= 85 || ml.ConfidencePercent >= 85) ? ThreatSeverity.Critical : ThreatSeverity.High,
                    DetectionMethod = triggeredByAi ? "Offline AI PE Classifier" : "PE Heuristic + AI",
                    HeuristicScore = Math.Max(effectiveScore, (int)Math.Round(ml.ConfidencePercent)),
                    AiConfidence = ml.ConfidencePercent,
                    Entropy = maxEntropy,
                    FileSize = fileSize,
                    IsDigitallySigned = isSigned,
                    SignerName = signerName,
                    ActionTaken = "Detected",
                    DetectedAt = DateTime.Now
                };
            }
        }

        return null;
    }

    public double CalculateShannonEntropy(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty) return 0.0;

        Span<int> counts = stackalloc int[256];
        foreach (var b in data)
        {
            counts[b]++;
        }

        double entropy = 0.0;
        double len = data.Length;
        for (int i = 0; i < 256; i++)
        {
            if (counts[i] == 0) continue;
            double p = counts[i] / len;
            entropy -= p * Math.Log2(p);
        }

        return Math.Round(entropy, 3);
    }

    public (bool IsPe, int HeuristicScore, double MaxSectionEntropy, List<string> MatchedIndicators) AnalyzePeAndHeuristics(ReadOnlySpan<byte> data)
    {
        var indicators = new List<string>();
        if (data.Length < 128 || data[0] != (byte)'M' || data[1] != (byte)'Z')
        {
            return (false, 0, 0, indicators);
        }

        int peOffset = BitConverter.ToInt32(data.Slice(0x3C, 4));
        if (peOffset <= 0 || peOffset + 24 >= data.Length)
        {
            return (false, 0, 0, indicators);
        }

        if (data[peOffset] != (byte)'P' || data[peOffset + 1] != (byte)'E' || data[peOffset + 2] != 0 || data[peOffset + 3] != 0)
        {
            return (false, 0, 0, indicators);
        }

        int score = 0;
        ushort numSections = BitConverter.ToUInt16(data.Slice(peOffset + 6, 2));
        ushort optionalHeaderSize = BitConverter.ToUInt16(data.Slice(peOffset + 20, 2));
        int sectionTableOffset = peOffset + 24 + optionalHeaderSize;

        double maxEntropy = CalculateShannonEntropy(data);
        if (maxEntropy >= 7.35)
        {
            score += 24;
            indicators.Add($"HighEntropy({maxEntropy:0.00})");
        }

        // Inspect PE section headers (40 bytes each)
        int rwxSections = 0;
        for (int s = 0; s < Math.Min((int)numSections, 16); s++)
        {
            int secOffset = sectionTableOffset + s * 40;
            if (secOffset + 40 > data.Length) break;

            var secName = Encoding.ASCII.GetString(data.Slice(secOffset, 8)).TrimEnd('\0');
            uint rawSize = BitConverter.ToUInt32(data.Slice(secOffset + 16, 4));
            uint rawPtr = BitConverter.ToUInt32(data.Slice(secOffset + 20, 4));
            uint characteristics = BitConverter.ToUInt32(data.Slice(secOffset + 36, 4));

            // IMAGE_SCN_MEM_EXECUTE (0x20000000) | IMAGE_SCN_MEM_WRITE (0x80000000)
            if ((characteristics & 0xA0000000) == 0xA0000000)
            {
                rwxSections++;
                indicators.Add($"RWX:{secName}");
            }

            if (secName.StartsWith("UPX", StringComparison.OrdinalIgnoreCase) || secName.Contains("vmp", StringComparison.OrdinalIgnoreCase))
            {
                score += 18;
                indicators.Add($"Packer:{secName}");
            }

            if (rawPtr > 0 && rawSize > 0 && rawPtr < data.Length)
            {
                int sliceLen = (int)Math.Min(rawSize, (uint)(data.Length - rawPtr));
                if (sliceLen >= 512)
                {
                    var secEntropy = CalculateShannonEntropy(data.Slice((int)rawPtr, sliceLen));
                    if (secEntropy > maxEntropy) maxEntropy = secEntropy;
                }
            }
        }

        if (rwxSections > 0)
        {
            score += Math.Min(30, rwxSections * 18);
        }

        // Inspect suspicious Win32 API imports present in binary strings/IAT
        var ascii = Encoding.ASCII.GetString(data);
        int importScore = 0;
        foreach (var (api, weight) in SuspiciousWin32Imports)
        {
            if (ascii.Contains(api, StringComparison.Ordinal))
            {
                importScore += weight;
                indicators.Add(api);
            }
        }

        // Only count strong combinations (e.g. injection triple or packer + APIs) to avoid false positives on benign apps
        if (importScore >= 38)
        {
            score += Math.Min(55, importScore);
        }

        return (true, Math.Min(100, score), Math.Round(maxEntropy, 2), indicators);
    }
}
