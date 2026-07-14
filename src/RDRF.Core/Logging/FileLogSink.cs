using System.Diagnostics;
using RDRF.Core.Configuration;

namespace RDRF.Core.Logging;

public class FileLogSink : ILogSink
{
    public string Name => "File";
    public LogLevel Level { get; set; } = LogLevel.Trace;
    public string LogDir { get; }

    private string? _currentDate;
    private string? _currentPath;
    private readonly object _lock = new();

    public FileLogSink(string? logDir = null)
    {
        LogDir = logDir ?? RdrfConfig.LogDir;
        Directory.CreateDirectory(LogDir);
    }

    public void Write(LogEntry entry)
    {
        string date = entry.Timestamp.ToString("yyyyMMdd");
        string path = Path.Combine(LogDir, $"rdrf-{date}.log");

        lock (_lock)
        {
            if (date != _currentDate)
            {
                _currentDate = date;
                _currentPath = path;
                // Trim old logs (keep 30 days)
                try
                {
                    foreach (var f in Directory.GetFiles(LogDir, "rdrf-*.log"))
                    {
                        var fi = new FileInfo(f);
                        if (fi.LastWriteTime < DateTime.Now.AddDays(-30))
                            fi.Delete();
                    }
                }
                catch { /* best effort */ }
            }

            string line = FormatEntry(entry);
            try { File.AppendAllText(_currentPath!, line); }
            catch (Exception ex) { Debug.WriteLine($"[FileLogSink] Write failed: {ex.Message}"); }
        }
    }

    private static string FormatEntry(LogEntry e)
    {
        string timestamp = e.Timestamp.ToString("yyyy-MM-dd HH:mm:ss.fff");
        string level = e.Level switch
        {
            LogLevel.Trace => "TRC",
            LogLevel.Debug => "DBG",
            LogLevel.Information => "INF",
            LogLevel.Warning => "WRN",
            LogLevel.Error => "ERR",
            LogLevel.Fatal => "FTL",
            _ => "???"
        };
        string elapsed = e.ElapsedMs.HasValue ? $" ({e.ElapsedMs}ms)" : "";
        string ex = e.Exception != null ? $"\n  EXCEPTION: {e.Exception}" : "";
        return $"{timestamp} [{level}] [{e.Category}] {e.Message}{elapsed}{ex}\n";
    }
}
