using System.Drawing;
using System.Drawing.Drawing2D;
using WinForms = System.Windows.Forms;

namespace KryvnixAntivirus.Desktop.Services;

public interface ISystemTrayService : IDisposable
{
    event EventHandler? OpenRequested;
    event EventHandler? QuickScanRequested;
    event EventHandler? ToggleRealtimeRequested;
    event EventHandler? ExitRequested;

    void Initialize();
    void UpdateStatusTooltip(string statusText, bool isProtected);
    void ShowBalloon(string title, string message, bool isWarning = false);
}

public sealed class SystemTrayService : ISystemTrayService
{
    private WinForms.NotifyIcon? _notifyIcon;
    private Icon? _shieldIcon;

    public event EventHandler? OpenRequested;
    public event EventHandler? QuickScanRequested;
    public event EventHandler? ToggleRealtimeRequested;
    public event EventHandler? ExitRequested;

    public void Initialize()
    {
        if (_notifyIcon is not null) return;

        _shieldIcon = CreateShieldIcon(Color.FromArgb(34, 197, 94));
        var menu = new WinForms.ContextMenuStrip();
        menu.Items.Add("Mở Kryvnix Antivirus", null, (_, _) => OpenRequested?.Invoke(this, EventArgs.Empty));
        menu.Items.Add("Quét nhanh ngay", null, (_, _) => QuickScanRequested?.Invoke(this, EventArgs.Empty));
        menu.Items.Add("Bật / Tắt Bảo vệ thời gian thực", null, (_, _) => ToggleRealtimeRequested?.Invoke(this, EventArgs.Empty));
        menu.Items.Add(new WinForms.ToolStripSeparator());
        menu.Items.Add("Thoát hoàn toàn", null, (_, _) => ExitRequested?.Invoke(this, EventArgs.Empty));

        _notifyIcon = new WinForms.NotifyIcon
        {
            Icon = _shieldIcon,
            Text = "Kryvnix Antivirus — Thiết bị an toàn",
            Visible = true,
            ContextMenuStrip = menu
        };

        _notifyIcon.DoubleClick += (_, _) => OpenRequested?.Invoke(this, EventArgs.Empty);
    }

    public void UpdateStatusTooltip(string statusText, bool isProtected)
    {
        if (_notifyIcon is null) return;
        var text = $"Kryvnix Antivirus — {statusText}";
        _notifyIcon.Text = text.Length > 63 ? text[..63] : text;

        var newIcon = CreateShieldIcon(isProtected ? Color.FromArgb(34, 197, 94) : Color.FromArgb(239, 68, 68));
        var oldIcon = _shieldIcon;
        _shieldIcon = newIcon;
        _notifyIcon.Icon = newIcon;
        oldIcon?.Dispose();
    }

    public void ShowBalloon(string title, string message, bool isWarning = false)
    {
        if (_notifyIcon is null) return;
        _notifyIcon.ShowBalloonTip(
            3500,
            title,
            message,
            isWarning ? WinForms.ToolTipIcon.Warning : WinForms.ToolTipIcon.Info);
    }

    private static Icon CreateShieldIcon(Color accentColor)
    {
        using var bmp = new Bitmap(32, 32);
        using var g = Graphics.FromImage(bmp);
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.Clear(Color.Transparent);

        using var path = new GraphicsPath();
        path.AddPolygon(new[]
        {
            new Point(16, 2),
            new Point(28, 7),
            new Point(27, 17),
            new Point(22, 25),
            new Point(16, 30),
            new Point(10, 25),
            new Point(5, 17),
            new Point(4, 7)
        });

        using var brush = new LinearGradientBrush(new Rectangle(0, 0, 32, 32), Color.FromArgb(17, 27, 40), accentColor, 45f);
        g.FillPath(brush, path);
        using var pen = new Pen(accentColor, 2f);
        g.DrawPath(pen, path);

        using var checkPen = new Pen(Color.White, 2.6f) { StartCap = LineCap.Round, EndCap = LineCap.Round };
        g.DrawLines(checkPen, new[] { new Point(10, 16), new Point(14, 20), new Point(22, 11) });

        var hIcon = bmp.GetHicon();
        return Icon.FromHandle(hIcon);
    }

    public void Dispose()
    {
        if (_notifyIcon is not null)
        {
            _notifyIcon.Visible = false;
            _notifyIcon.Dispose();
            _notifyIcon = null;
        }
        _shieldIcon?.Dispose();
        _shieldIcon = null;
    }
}
