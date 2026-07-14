namespace RDRF.Core.Logging;

public class ConsoleLogSink : ILogSink
{
    public string Name => "Console";
    public LogLevel Level { get; set; } = LogLevel.Warning;

    public void Write(LogEntry entry)
    {
        string line = FormatEntry(entry);
        if (entry.Level >= LogLevel.Error)
            Console.Error.WriteLine(line);
        else
            Console.WriteLine(line);
    }

    private static string FormatEntry(LogEntry e)
    {
        string ts = e.Timestamp.ToString("HH:mm:ss.fff");
        return $"{ts} [{e.Level}] [{e.Category}] {e.Message}";
    }
}
