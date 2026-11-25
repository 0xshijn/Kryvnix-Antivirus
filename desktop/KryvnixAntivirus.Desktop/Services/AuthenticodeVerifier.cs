using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace KryvnixAntivirus.Desktop.Services;

public sealed record AuthenticodeResult(bool IsValidSignature, string SignerName, string Status);

public interface IAuthenticodeVerifier
{
    AuthenticodeResult VerifyFile(string filePath);
}

/// <summary>
/// Real Win32 Authenticode verifier supporting BOTH embedded PE signatures (WTD_CHOICE_FILE)
/// and Windows Security Catalog signatures (CryptCATAdmin* for inbox OS binaries like cmd.exe).
/// </summary>
public sealed partial class AuthenticodeVerifier : IAuthenticodeVerifier
{
    private static readonly Guid WintrustActionGenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    private const uint WtdUiNone = 2;
    private const uint WtdRevokeNone = 0;
    private const uint WtdChoiceFile = 1;
    private const uint WtdChoiceCatalog = 2;
    private const uint WtdStateActionVerify = 1;
    private const uint WtdStateActionClose = 2;
    private const uint WtdCacheOnlyUrlRetrieval = 0x00000004;
    private const int TrustENoSignature = unchecked((int)0x800B0100);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustFileInfo
    {
        public uint cbStruct;
        public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustCatalogInfo
    {
        public uint cbStruct;
        public uint dwCatalogVersion;
        public string pcwszCatalogFilePath;
        public string pcwszMemberTag;
        public string pcwszMemberFilePath;
        public IntPtr hMemberFile;
        public IntPtr pbCalculatedFileHash;
        public uint cbCalculatedFileHash;
        public IntPtr pcCatalogContext;
        public IntPtr hCatAdmin;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustData
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pUnionInfo;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public string? pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CatalogInfo
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string wszCatalogFile;
    }

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false, CharSet = CharSet.Unicode)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WinTrustData pWVTData);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptCATAdminAcquireContext2(out IntPtr phCatAdmin, IntPtr pgSubsystem, string pwszHashAlgorithm, IntPtr pStrongHashPolicy, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr hCatAdmin, IntPtr hFile, ref uint pcbHash, byte[]? pbHash, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, byte[] pbHash, uint cbHash, uint dwFlags, IntPtr phPrevCatInfo);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptCATCatalogInfoFromContext(IntPtr hCatInfo, ref CatalogInfo psCatInfo, uint dwFlags);

    public AuthenticodeResult VerifyFile(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
        {
            return new AuthenticodeResult(false, string.Empty, "NotFound");
        }

        // 1. Check embedded PE Authenticode signature first
        var embedded = VerifyEmbeddedSignature(filePath);
        if (embedded.IsValidSignature)
        {
            return embedded;
        }

        // 2. If TRUST_E_NOSIGNATURE, check Windows Security Catalog (CatRoot) for OS binaries
        if (embedded.Status == $"Untrusted(0x{TrustENoSignature:X8})")
        {
            var catResult = VerifyCatalogSignature(filePath);
            if (catResult.IsValidSignature)
            {
                return catResult;
            }
        }

        return embedded;
    }

    private static AuthenticodeResult VerifyEmbeddedSignature(string filePath)
    {
        IntPtr fileInfoPtr = IntPtr.Zero;
        try
        {
            var fileInfo = new WinTrustFileInfo
            {
                cbStruct = (uint)Marshal.SizeOf<WinTrustFileInfo>(),
                pcwszFilePath = filePath
            };

            fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
            Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);

            var data = new WinTrustData
            {
                cbStruct = (uint)Marshal.SizeOf<WinTrustData>(),
                dwUIChoice = WtdUiNone,
                fdwRevocationChecks = WtdRevokeNone,
                dwUnionChoice = WtdChoiceFile,
                pUnionInfo = fileInfoPtr,
                dwStateAction = WtdStateActionVerify,
                dwProvFlags = WtdCacheOnlyUrlRetrieval
            };

            var action = WintrustActionGenericVerifyV2;
            int result = WinVerifyTrust(IntPtr.Zero, ref action, ref data);
            data.dwStateAction = WtdStateActionClose;
            _ = WinVerifyTrust(IntPtr.Zero, ref action, ref data);

            if (result == 0)
            {
                return new AuthenticodeResult(true, ExtractSignerName(filePath), "Trusted (Embedded)");
            }

            return new AuthenticodeResult(false, string.Empty, $"Untrusted(0x{result:X8})");
        }
        catch
        {
            return new AuthenticodeResult(false, string.Empty, "Unavailable");
        }
        finally
        {
            if (fileInfoPtr != IntPtr.Zero) Marshal.FreeHGlobal(fileInfoPtr);
        }
    }

    private static AuthenticodeResult VerifyCatalogSignature(string filePath)
    {
        IntPtr hCatAdmin = IntPtr.Zero;
        IntPtr hCatInfo = IntPtr.Zero;
        IntPtr catUnionPtr = IntPtr.Zero;
        try
        {
            if (!CryptCATAdminAcquireContext2(out hCatAdmin, IntPtr.Zero, "SHA256", IntPtr.Zero, 0))
            {
                return new AuthenticodeResult(false, string.Empty, "CatalogContextFailed");
            }

            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            IntPtr hFile = fs.SafeFileHandle.DangerousGetHandle();

            uint hashSize = 0;
            _ = CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, ref hashSize, null, 0);
            if (hashSize == 0) return new AuthenticodeResult(false, string.Empty, "CatalogHashFailed");

            var hashBytes = new byte[hashSize];
            if (!CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, ref hashSize, hashBytes, 0))
            {
                return new AuthenticodeResult(false, string.Empty, "CatalogHashFailed");
            }

            hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hashBytes, hashSize, 0, IntPtr.Zero);
            if (hCatInfo == IntPtr.Zero)
            {
                return new AuthenticodeResult(false, string.Empty, "NotInCatalog");
            }

            var ci = new CatalogInfo { cbStruct = (uint)Marshal.SizeOf<CatalogInfo>() };
            if (!CryptCATCatalogInfoFromContext(hCatInfo, ref ci, 0))
            {
                return new AuthenticodeResult(false, string.Empty, "CatalogInfoFailed");
            }

            var memberTag = Convert.ToHexString(hashBytes);
            var wtCat = new WinTrustCatalogInfo
            {
                cbStruct = (uint)Marshal.SizeOf<WinTrustCatalogInfo>(),
                pcwszCatalogFilePath = ci.wszCatalogFile,
                pcwszMemberTag = memberTag,
                pcwszMemberFilePath = filePath,
                hMemberFile = hFile
            };

            catUnionPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustCatalogInfo>());
            Marshal.StructureToPtr(wtCat, catUnionPtr, false);

            var data = new WinTrustData
            {
                cbStruct = (uint)Marshal.SizeOf<WinTrustData>(),
                dwUIChoice = WtdUiNone,
                fdwRevocationChecks = WtdRevokeNone,
                dwUnionChoice = WtdChoiceCatalog,
                pUnionInfo = catUnionPtr,
                dwStateAction = WtdStateActionVerify,
                dwProvFlags = WtdCacheOnlyUrlRetrieval
            };

            var action = WintrustActionGenericVerifyV2;
            int result = WinVerifyTrust(IntPtr.Zero, ref action, ref data);
            data.dwStateAction = WtdStateActionClose;
            _ = WinVerifyTrust(IntPtr.Zero, ref action, ref data);

            if (result == 0)
            {
                var signer = ExtractSignerName(ci.wszCatalogFile);
                return new AuthenticodeResult(true, string.IsNullOrWhiteSpace(signer) ? "Microsoft Windows (Catalog)" : signer, "Trusted (Catalog)");
            }

            return new AuthenticodeResult(false, string.Empty, $"CatalogUntrusted(0x{result:X8})");
        }
        catch
        {
            return new AuthenticodeResult(false, string.Empty, "CatalogUnavailable");
        }
        finally
        {
            if (catUnionPtr != IntPtr.Zero) Marshal.FreeHGlobal(catUnionPtr);
            if (hCatInfo != IntPtr.Zero && hCatAdmin != IntPtr.Zero) CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
            if (hCatAdmin != IntPtr.Zero) CryptCATAdminReleaseContext(hCatAdmin, 0);
        }
    }

    private static string ExtractSignerName(string filePath)
    {
        try
        {
#pragma warning disable SYSLIB0057
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(filePath));
#pragma warning restore SYSLIB0057
            var cn = cert.GetNameInfo(X509NameType.SimpleName, false);
            return string.IsNullOrWhiteSpace(cn) ? cert.Subject : cn;
        }
        catch
        {
            return "Verified Windows Publisher";
        }
    }
}
