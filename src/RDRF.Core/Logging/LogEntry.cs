namespace RDRF.Core.Logging;

public class LogEntry
{
    public DateTime Timestamp { get; set; } = DateTime.Now;
    public LogLevel Level { get; set; }
    public string Category { get; set; } = "";
    public string Message { get; set; } = "";
    public string? Exception { get; set; }
    public long? ElapsedMs { get; set; }
}
