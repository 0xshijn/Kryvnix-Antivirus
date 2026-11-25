using System.Text;
using KryvnixAntivirus.Desktop.Models;

namespace KryvnixAntivirus.Desktop.Services;

public interface IPeMlClassifierService
{
    PeAiClassificationResult ClassifyPe(ReadOnlySpan<byte> data, bool isDigitallySigned);
}

/// <summary>
/// Offline lightweight Logistic/Perceptron PE Malware Classifier using 8 static PE structural features.
/// Runs 100% locally without cloud dependencies in &lt;2ms per binary.
/// </summary>
public sealed class PeMlClassifierService : IPeMlClassifierService
{
    private static readonly string[] HighRiskApis =
    [
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtUnmapViewOfSection",
        "SetWindowsHookEx", "GetAsyncKeyState", "CryptEncrypt", "URLDownloadToFile",
        "IsDebuggerPresent", "LoadLibraryA", "GetProcAddress", "AdjustTokenPrivileges"
    ];

    public PeAiClassificationResult ClassifyPe(ReadOnlySpan<byte> data, bool isDigitallySigned)
    {
        var result = new PeAiClassificationResult();
        if (data.Length < 256 || data[0] != (byte)'M' || data[1] != (byte)'Z')
        {
            return result;
        }

        int peOffset = BitConverter.ToInt32(data.Slice(0x3C, 4));
        if (peOffset <= 0 || peOffset + 24 >= data.Length) return result;
        if (data[peOffset] != (byte)'P' || data[peOffset + 1] != (byte)'E' || data[peOffset + 2] != 0 || data[peOffset + 3] != 0)
        {
            return result;
        }

        result.IsPe = true;

        ushort numSections = BitConverter.ToUInt16(data.Slice(peOffset + 6, 2));
        ushort optionalHeaderSize = BitConverter.ToUInt16(data.Slice(peOffset + 20, 2));
        int sectionTableOffset = peOffset + 24 + optionalHeaderSize;

        double overallEntropy = ComputeEntropy(data);
        double maxSecEntropy = overallEntropy;
        int rwxCount = 0;
        int packerCount = 0;
        int sizeAnomalyCount = 0;

        int inspectedSections = Math.Min((int)numSections, 16);
        for (int i = 0; i < inspectedSections; i++)
        {
            int off = sectionTableOffset + i * 40;
            if (off + 40 > data.Length) break;

            var name = Encoding.ASCII.GetString(data.Slice(off, 8)).TrimEnd('\0');
            uint virtSize = BitConverter.ToUInt32(data.Slice(off + 8, 4));
            uint rawSize = BitConverter.ToUInt32(data.Slice(off + 16, 4));
            uint rawPtr = BitConverter.ToUInt32(data.Slice(off + 20, 4));
            uint chars = BitConverter.ToUInt32(data.Slice(off + 36, 4));

            if ((chars & 0xA0000000) == 0xA0000000) rwxCount++;
            if (name.StartsWith("UPX", StringComparison.OrdinalIgnoreCase) ||
                name.Contains("vmp", StringComparison.OrdinalIgnoreCase) ||
                name.Contains("aspack", StringComparison.OrdinalIgnoreCase))
            {
                packerCount++;
            }

            if (rawSize > 0 && virtSize > rawSize * 4) sizeAnomalyCount++;

            if (rawPtr > 0 && rawSize > 0 && rawPtr < data.Length)
            {
                int sliceLen = (int)Math.Min(rawSize, (uint)(data.Length - rawPtr));
                if (sliceLen >= 512)
                {
                    double e = ComputeEntropy(data.Slice((int)rawPtr, sliceLen));
                    if (e > maxSecEntropy) maxSecEntropy = e;
                }
            }
        }

        var ascii = Encoding.ASCII.GetString(data);
        int apiHits = 0;
        foreach (var api in HighRiskApis)
        {
            if (ascii.Contains(api, StringComparison.Ordinal)) apiHits++;
        }

        // Normalized feature vector x[0..7]
        double fEntropy = Math.Clamp((overallEntropy - 5.5) / 2.5, 0.0, 1.0);
        double fMaxSecEntropy = Math.Clamp((maxSecEntropy - 6.0) / 2.0, 0.0, 1.0);
        double fRwxRatio = inspectedSections > 0 ? Math.Clamp((double)rwxCount / inspectedSections, 0.0, 1.0) : 0.0;
        double fPacker = packerCount > 0 ? 1.0 : 0.0;
        double fApiDensity = Math.Clamp(apiHits / 6.0, 0.0, 1.0);
        double fSizeAnomaly = sizeAnomalyCount > 0 ? 1.0 : 0.0;
        double fSectionAnomaly = (numSections == 0 || numSections > 10) ? 1.0 : 0.0;
        double fSigned = isDigitallySigned ? 1.0 : 0.0;

        // Pre-calibrated logistic regression weights (bias + weighted features)
        double logit = -3.15
            + 1.35 * fEntropy
            + 1.50 * fMaxSecEntropy
            + 2.40 * fRwxRatio
            + 1.95 * fPacker
            + 3.10 * fApiDensity
            + 0.90 * fSizeAnomaly
            + 0.70 * fSectionAnomaly
            - 2.85 * fSigned;

        double prob = 1.0 / (1.0 + Math.Exp(-logit));
        result.MalwareProbability = Math.Round(prob, 4);

        if (fApiDensity >= 0.45) result.TopFeatures.Add($"SuspiciousAPIs({apiHits})");
        if (fRwxRatio > 0) result.TopFeatures.Add($"RWX_Sections({rwxCount})");
        if (fPacker > 0) result.TopFeatures.Add("PackerSignature");
        if (maxSecEntropy >= 7.2) result.TopFeatures.Add($"HighEntropy({maxSecEntropy:0.00})");
        if (isDigitallySigned) result.TopFeatures.Add("AuthenticodeTrusted");

        return result;
    }

    private static double ComputeEntropy(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty) return 0.0;
        Span<int> counts = stackalloc int[256];
        foreach (var b in data) counts[b]++;
        double entropy = 0.0;
        double len = data.Length;
        for (int i = 0; i < 256; i++)
        {
            if (counts[i] == 0) continue;
            double p = counts[i] / len;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }
}
