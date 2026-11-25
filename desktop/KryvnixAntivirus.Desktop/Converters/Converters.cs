using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using KryvnixAntivirus.Desktop.Models;

namespace KryvnixAntivirus.Desktop.Converters;

public sealed class BoolToVisibilityConverter : IValueConverter
{
    public bool Invert { get; set; }

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        bool flag = value is bool b && b;
        if (Invert) flag = !flag;
        return flag ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => value is Visibility v && (Invert ? v != Visibility.Visible : v == Visibility.Visible);
}

public sealed class InverseBoolConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        => value is bool b ? !b : true;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => value is bool b ? !b : false;
}

public sealed class PositiveIntToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        bool isPositive = value is int count && count > 0;
        bool invert = string.Equals(parameter?.ToString(), "Invert", StringComparison.OrdinalIgnoreCase);
        if (invert) isPositive = !isPositive;
        return isPositive ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

public sealed class HexToBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is string hex && !string.IsNullOrWhiteSpace(hex))
        {
            try
            {
                return (SolidColorBrush)new BrushConverter().ConvertFromString(hex)!;
            }
            catch
            {
                // fallback below
            }
        }
        return Brushes.MediumSeaGreen;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

public sealed class HexToColorConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is string hex && !string.IsNullOrWhiteSpace(hex))
        {
            try
            {
                return (Color)ColorConverter.ConvertFromString(hex);
            }
            catch
            {
                // fallback below
            }
        }
        return Color.FromRgb(34, 197, 94);
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

public sealed class DotNumberConverter : IValueConverter
{
    private static readonly CultureInfo ViCulture = new("vi-VN");

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        return value switch
        {
            long l => l.ToString("N0", ViCulture),
            int i => i.ToString("N0", ViCulture),
            double d => d.ToString("N0", ViCulture),
            _ => value?.ToString() ?? "0"
        };
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

public sealed class RelativeTimeConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is not DateTime dt) return "Chưa có";
        var today = DateTime.Today;
        if (dt.Date == today) return $"Hôm nay, {dt:HH:mm}";
        if (dt.Date == today.AddDays(-1)) return $"Hôm qua, {dt:HH:mm}";
        return dt.ToString("dd/MM/yyyy, HH:mm");
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

public sealed class FileSizeConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        long bytes = value switch
        {
            long l => l,
            int i => i,
            _ => 0
        };

        if (bytes < 1024) return $"{bytes} B";
        if (bytes < 1024 * 1024) return $"{bytes / 1024.0:0.0} KB";
        if (bytes < 1024L * 1024 * 1024) return $"{bytes / (1024.0 * 1024):0.00} MB";
        return $"{bytes / (1024.0 * 1024 * 1024):0.00} GB";
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

public sealed class SeverityToColorBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var sev = value is ThreatSeverity s ? s : ThreatSeverity.Low;
        var hex = sev switch
        {
            ThreatSeverity.Critical => "#EF4444",
            ThreatSeverity.High => "#F97316",
            ThreatSeverity.Medium => "#F59E0B",
            _ => "#22C55E"
        };
        return (SolidColorBrush)new BrushConverter().ConvertFromString(hex)!;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

public sealed class SeverityToBgBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var sev = value is ThreatSeverity s ? s : ThreatSeverity.Low;
        var hex = sev switch
        {
            ThreatSeverity.Critical => "#33161E",
            ThreatSeverity.High => "#332016",
            ThreatSeverity.Medium => "#2F2614",
            _ => "#143025"
        };
        return (SolidColorBrush)new BrushConverter().ConvertFromString(hex)!;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

public sealed class ActivityTypeToAccentBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var type = value is ActivityEventType t ? t : ActivityEventType.SystemInfo;
        var hex = type switch
        {
            ActivityEventType.ScanCompleted => "#22C55E",
            ActivityEventType.MalwareDetected => "#EF4444",
            ActivityEventType.FileQuarantined => "#F59E0B",
            ActivityEventType.FileRestored => "#38BDF8",
            ActivityEventType.FileDeleted => "#94A3B8",
            ActivityEventType.DatabaseUpdated => "#38BDF8",
            ActivityEventType.ProtectionChanged => "#22C55E",
            _ => "#94A3B8"
        };
        return (SolidColorBrush)new BrushConverter().ConvertFromString(hex)!;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

public sealed class ActivityTypeToBadgeBgConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var type = value is ActivityEventType t ? t : ActivityEventType.SystemInfo;
        var hex = type switch
        {
            ActivityEventType.ScanCompleted => "#143426",
            ActivityEventType.MalwareDetected => "#3A1820",
            ActivityEventType.FileQuarantined => "#332615",
            ActivityEventType.FileRestored => "#142A3A",
            ActivityEventType.DatabaseUpdated => "#142A3A",
            ActivityEventType.ProtectionChanged => "#143426",
            _ => "#1E293B"
        };
        return (SolidColorBrush)new BrushConverter().ConvertFromString(hex)!;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

public sealed class ActivityTypeToIconGeometryConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var type = value is ActivityEventType t ? t : ActivityEventType.SystemInfo;
        var key = type switch
        {
            ActivityEventType.ScanCompleted => "IconCheckCircle",
            ActivityEventType.MalwareDetected => "IconAlertOctagon",
            ActivityEventType.FileQuarantined => "IconLock",
            ActivityEventType.FileRestored => "IconRestore",
            ActivityEventType.FileDeleted => "IconTrash",
            ActivityEventType.DatabaseUpdated => "IconSync",
            ActivityEventType.ProtectionChanged => "IconShieldCheck",
            _ => "IconShieldCheck"
        };

        return Application.Current?.TryFindResource(key) ?? Geometry.Empty;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

public sealed class BoolToStatusTextConverter : IValueConverter
{
    public string TrueText { get; set; } = "Đang hoạt động";
    public string FalseText { get; set; } = "Đã tắt";

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        => value is bool b && b ? TrueText : FalseText;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

public sealed class BoolToStatusBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var active = value is bool b && b;
        var hex = active ? "#22C55E" : "#94A3B8";
        return (SolidColorBrush)new BrushConverter().ConvertFromString(hex)!;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

public sealed class BoolToStatusPillBgConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var active = value is bool b && b;
        var hex = active ? "#123526" : "#1E293B";
        return (SolidColorBrush)new BrushConverter().ConvertFromString(hex)!;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
