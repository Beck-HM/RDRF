using System.Diagnostics;

namespace RDRF.Mcp.Wpf;

public class WpfAppController : IDisposable
{
    private Process? _process;
    private bool _disposed;

    public string AppExePath { get; }

    public WpfAppController(string appExePath)
    {
        AppExePath = appExePath;
    }

    public Process Launch()
    {
        if (_process != null && !_process.HasExited)
            return _process;

        _process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = AppExePath,
                UseShellExecute = true,
            },
            EnableRaisingEvents = true,
        };
        _process.Start();
        return _process;
    }

    public void Close()
    {
        if (_process != null && !_process.HasExited)
        {
            _process.CloseMainWindow();
            if (!_process.WaitForExit(5000))
                _process.Kill();
            _process.Dispose();
            _process = null;
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        Close();
        _disposed = true;
    }
}
