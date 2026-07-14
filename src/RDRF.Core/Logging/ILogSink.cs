namespace RDRF.Core.Logging;

public interface ILogSink
{
    string Name { get; }
    LogLevel Level { get; set; }
    void Write(LogEntry entry);
}
