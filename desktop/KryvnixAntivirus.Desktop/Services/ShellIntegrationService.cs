using System.Diagnostics;
using Microsoft.Win32;

namespace KryvnixAntivirus.Desktop.Services;

public interface IShellIntegrationService
{
    bool IsContextMenuRegistered();
    bool RegisterContextMenu();
    bool UnregisterContextMenu();
}

public sealed class ShellIntegrationService : IShellIntegrationService
{
    private const string FileShellKey = @"Software\Classes\*\shell\KryvnixAntivirusScan";
    private const string DirShellKey = @"Software\Classes\Directory\shell\KryvnixAntivirusScan";

    public bool IsContextMenuRegistered()
    {
        try
        {
            using var k = Registry.CurrentUser.OpenSubKey(FileShellKey, false);
            return k is not null;
        }
        catch
        {
            return false;
        }
    }

    public bool RegisterContextMenu()
    {
        try
        {
            var exePath = Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule?.FileName;
            if (string.IsNullOrWhiteSpace(exePath)) return false;

            RegisterKey(FileShellKey, exePath);
            RegisterKey(DirShellKey, exePath);
            return true;
        }
        catch
        {
            return false;
        }
    }

    public bool UnregisterContextMenu()
    {
        try
        {
            Registry.CurrentUser.DeleteSubKeyTree(FileShellKey, throwOnMissingSubKey: false);
            Registry.CurrentUser.DeleteSubKeyTree(DirShellKey, throwOnMissingSubKey: false);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static void RegisterKey(string keyPath, string exePath)
    {
        using var root = Registry.CurrentUser.CreateSubKey(keyPath);
        root.SetValue(string.Empty, "Quét bằng Kryvnix Antivirus");
        root.SetValue("Icon", $"\"{exePath}\",0");

        using var cmd = root.CreateSubKey("command");
        cmd.SetValue(string.Empty, $"\"{exePath}\" --scan \"%1\"");
    }
}
