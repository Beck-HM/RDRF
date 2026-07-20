namespace RDRF.Core;

public static class FileSizeFormatter
{
    public static string FormatBytes(long bytes) => FormatBytes(bytes, useDecimal: false);

    public static string FormatBytes(long bytes, bool useDecimal)
    {
        long divisor = useDecimal ? 1000 : 1024;
        string[] units = useDecimal
            ? new[] { "B", "KB", "MB", "GB", "TB" }
            : new[] { "B", "KiB", "MiB", "GiB", "TiB" };

        double size = bytes;
        int unitIndex = 0;

        while (size >= divisor && unitIndex < units.Length - 1)
        {
            size /= divisor;
            unitIndex++;
        }

        return unitIndex == 0
            ? $"{bytes} {units[0]}"
            : $"{size:F2} {units[unitIndex]}";
    }
}
