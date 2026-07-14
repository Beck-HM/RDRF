using System.Diagnostics;

namespace RDRF.Core.Logging;

public class DebugLogSink : ILogSink
{
    public string Name => "Debug";
    public LogLevel Level { get; set; } = LogLevel.Trace;

    public void Write(LogEntry entry)
    {
        string line = $"[RDRF] [{entry.Level}] [{entry.Category}] {entry.Message}";
        if (entry.ElapsedMs.HasValue)
            line += $" ({entry.ElapsedMs}ms)";
        Debug.WriteLine(line);
        if (entry.Exception != null)
            Debug.WriteLine($"  EXCEPTION: {entry.Exception}");
    }
}
