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
    }

    /// <summary>
    /// Send a JSON message to the RDRF.App main window via WM_COPYDATA.
    /// </summary>
    public bool SendIpcMessage(string json)
    {
        // Find RDRF.App main window by process name
        IntPtr mainHwnd = IntPtr.Zero;
        if (_process != null && !_process.HasExited)
        {
            mainHwnd = _process.MainWindowHandle;
            if (mainHwnd == IntPtr.Zero)
            {
                _process.WaitForInputIdle(5000);
                mainHwnd = _process.MainWindowHandle;
            }
        }

        // Fallback: search for any RDRF.App window
        if (mainHwnd == IntPtr.Zero)
        {
            var procs = Process.GetProcessesByName("RDRF.App");
            foreach (var p in procs)
            {
                if (p.MainWindowHandle != IntPtr.Zero)
                {
                    mainHwnd = p.MainWindowHandle;
                    _process = p;
                    break;
                }
            }
        }

        if (mainHwnd == IntPtr.Zero)
            return false;

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
            int result = SendMessage(mainHwnd, WM_COPYDATA, IntPtr.Zero, ref cds);
            return result != 0;
        }
        finally
        {
            Marshal.FreeHGlobal(cds.lpData);
        }
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
