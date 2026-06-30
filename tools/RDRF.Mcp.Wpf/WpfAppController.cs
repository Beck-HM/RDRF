using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

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

        // Kill any remaining RDRF.App processes (orphans from previous runs)
        foreach (var p in Process.GetProcessesByName("RDRF.App"))
        {
            try
            {
                p.CloseMainWindow();
                if (!p.WaitForExit(3000))
                    p.Kill();
                p.Dispose();
            }
            catch { }
        }
    }

    /// <summary>
    /// Send a JSON message to the RDRF.App main window via WM_COPYDATA.
    /// Retries up to 10 times with 1s delay to wait for window readiness.
    /// </summary>
    public bool SendIpcMessage(string json)
    {
        for (int attempt = 0; attempt < 10; attempt++)
        {
            IntPtr hwnd = FindTargetWindow();
            if (hwnd != IntPtr.Zero)
            {
                byte[] bytes = Encoding.UTF8.GetBytes(json);
                var cds = new COPYDATASTRUCT
                {
                    dwData = IntPtr.Zero,
                    cbData = bytes.Length,
                    lpData = Marshal.AllocHGlobal(bytes.Length),
                };
                Marshal.Copy(bytes, 0, cds.lpData, bytes.Length);

                try
                {
                    SendMessage(hwnd, WM_COPYDATA, IntPtr.Zero, ref cds);
                    return true;
                }
                finally
                {
                    Marshal.FreeHGlobal(cds.lpData);
                }
            }
            Thread.Sleep(1000);
        }
        return false;
    }

    private IntPtr FindTargetWindow()
    {
        if (_process != null && !_process.HasExited)
        {
            IntPtr hwnd = _process.MainWindowHandle;
            if (hwnd == IntPtr.Zero)
            {
                _process.WaitForInputIdle(5000);
                hwnd = _process.MainWindowHandle;
            }
            if (hwnd != IntPtr.Zero)
                return hwnd;
        }

        var procs = Process.GetProcessesByName("RDRF.App");
        foreach (var p in procs)
        {
            if (p.MainWindowHandle != IntPtr.Zero)
            {
                _process = p;
                return p.MainWindowHandle;
            }
        }
        return IntPtr.Zero;
    }

    public void Dispose()
    {
        if (_disposed) return;
        Close();
        _disposed = true;
    }

    private const int WM_COPYDATA = 0x004A;

    [StructLayout(LayoutKind.Sequential)]
    private struct COPYDATASTRUCT
    {
        public IntPtr dwData;
        public int cbData;
        public IntPtr lpData;
    }

    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    private static extern int SendMessage(IntPtr hwnd, int msg, IntPtr wParam, ref COPYDATASTRUCT lParam);
}
