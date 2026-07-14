using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace RDRF.Mcp.Wpf;

public class WpfAppController : IDisposable
{
    private Process? _process;
    private bool _disposed;
    private string? _ipcToken;

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
    /// Auto-injects the IPC auth token and encrypts with DPAPI.
    /// Retries up to 10 times with 1s delay to wait for window readiness.
    /// </summary>
    public bool SendIpcMessage(string json)
    {
        EnsureIpcToken();
        if (_ipcToken == null) return false;

        // Inject token into the JSON payload
        string tokenMsg = json.TrimEnd('}') + $@",""token"":""{_ipcToken}""}}";

        for (int attempt = 0; attempt < 10; attempt++)
        {
            IntPtr hwnd = FindTargetWindow();
            if (hwnd != IntPtr.Zero)
            {
                SendEncryptedMessage(hwnd, tokenMsg);
                return true;
            }
            Thread.Sleep(1000);
        }
        return false;
    }

    private static void SendEncryptedMessage(IntPtr hwnd, string json)
    {
        byte[] raw = Encoding.UTF8.GetBytes(json);
        byte[] enc = ProtectedData.Protect(raw, null, DataProtectionScope.CurrentUser);
        byte[] packet = new byte[5 + enc.Length];
        packet[0] = 0x01;
        BitConverter.GetBytes(enc.Length).CopyTo(packet, 1);
        Buffer.BlockCopy(enc, 0, packet, 5, enc.Length);

        var cds = new COPYDATASTRUCT
        {
            dwData = IntPtr.Zero,
            cbData = packet.Length,
            lpData = Marshal.AllocHGlobal(packet.Length),
        };
        Marshal.Copy(packet, 0, cds.lpData, packet.Length);

        try
        {
            SendMessage(hwnd, WM_COPYDATA, IntPtr.Zero, ref cds);
        }
        finally
        {
            Marshal.FreeHGlobal(cds.lpData);
        }
    }

    private void EnsureIpcToken()
    {
        if (_ipcToken != null) return;

        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string tokenFile = Path.Combine(localAppData, "RDRF", "ipc_token");
        if (File.Exists(tokenFile))
        {
            _ipcToken = File.ReadAllText(tokenFile).Trim();
        }
        else
        {
            var exeDir = Path.GetDirectoryName(AppExePath);
            if (exeDir != null)
            {
                string configDir = Path.Combine(exeDir, ".rdrf");
                string configTokenFile = Path.Combine(configDir, "ipc_token");
                if (File.Exists(configTokenFile))
                    _ipcToken = File.ReadAllText(configTokenFile).Trim();
            }
        }
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
