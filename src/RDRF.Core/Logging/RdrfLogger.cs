using System.Diagnostics;

namespace RDRF.Core.Logging;

public class RdrfLogger
{
    public static RdrfLogger Default { get; } = CreateDefault();

    private static RdrfLogger CreateDefault()
    {
        var logger = new RdrfLogger();
        logger.AddSink(new DebugLogSink());
        return logger;
    }

    private readonly List<ILogSink> _sinks = new();
    private readonly object _lock = new();

    public void AddSink(ILogSink sink)
    {
        lock (_lock) _sinks.Add(sink);
    }

    public void RemoveSink(string name)
    {
        lock (_lock) _sinks.RemoveAll(s => s.Name == name);
    }

    public void Log(LogLevel level, string category, string message, Exception? ex = null, long? elapsedMs = null)
    {
        var entry = new LogEntry
        {
            Timestamp = DateTime.Now,
            Level = level,
            Category = category,
            Message = message,
            Exception = ex?.ToString(),
            ElapsedMs = elapsedMs,
        };

        List<ILogSink>? snapshot;
        lock (_lock) snapshot = _sinks.ToList();

        foreach (var sink in snapshot)
        {
            if (level >= sink.Level)
            {
                try { sink.Write(entry); }
                catch (Exception e) { System.Diagnostics.Debug.WriteLine($"[RdrfLogger] Sink '{sink.Name}' failed: {e.Message}"); }
            }
        }
    }

    public void Trace(string category, string message) => Log(LogLevel.Trace, category, message);
    public void Debug(string category, string message) => Log(LogLevel.Debug, category, message);
    public void Info(string category, string message) => Log(LogLevel.Information, category, message);
    public void Warn(string category, string message, Exception? ex = null) => Log(LogLevel.Warning, category, message, ex);
    public void Error(string category, string message, Exception? ex = null) => Log(LogLevel.Error, category, message, ex);
    public void Fatal(string category, string message, Exception? ex = null) => Log(LogLevel.Fatal, category, message, ex);

    public IDisposable BeginScope(string category, string operation)
    {
        Info(category, $"[SCOPE] {operation} started");
        return new ScopeGuard(this, category, operation);
    }

    private sealed class ScopeGuard : IDisposable
    {
        private readonly RdrfLogger _logger;
        private readonly string _category;
        private readonly string _operation;
        private readonly long _start;
        public ScopeGuard(RdrfLogger logger, string category, string operation)
        {
            _logger = logger; _category = category; _operation = operation;
            _start = Stopwatch.GetTimestamp();
        }
        public void Dispose()
        {
            long ms = (Stopwatch.GetTimestamp() - _start) * 1000 / Stopwatch.Frequency;
            _logger.Log(LogLevel.Information, _category, $"[SCOPE] {_operation} completed", elapsedMs: ms);
        }
    }
}
