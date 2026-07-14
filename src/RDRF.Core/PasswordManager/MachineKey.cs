using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace RDRF.Core.PasswordManager;

internal static partial class MachineKey
{
    private static byte[]? _cached;

    public static byte[] Derive()
    {
        if (_cached != null) return _cached;

        string machineId = GetMachineId();
        byte[] key = SHA256.HashData(Encoding.UTF8.GetBytes(machineId + "RDRF_PW_V1"));
        _cached = key;
        return key;
    }

    public static void Clear()
    {
        if (_cached != null)
        {
            CryptographicOperations.ZeroMemory(_cached);
            _cached = null;
        }
    }

    private static string GetMachineId()
    {
        if (OperatingSystem.IsWindows())
        {
            try
            {
                using var regKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Cryptography");
                return regKey?.GetValue("MachineGuid")?.ToString() ?? "WIN_FALLBACK";
            }
            catch { return "WIN_FALLBACK"; }
        }

        if (OperatingSystem.IsLinux())
        {
            try
            {
                string path = "/etc/machine-id";
                return File.Exists(path) ? File.ReadAllText(path).Trim() : "LINUX_FALLBACK";
            }
            catch { return "LINUX_FALLBACK"; }
        }

        if (OperatingSystem.IsMacOS())
        {
            try
            {
                var psi = new ProcessStartInfo("ioreg", "-rd1 -c IOPlatformExpertDevice")
                {
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                };
                using var proc = Process.Start(psi);
                if (proc != null)
                {
                    string output = proc.StandardOutput.ReadToEnd();
                    var match = UuidRegex().Match(output);
                    if (match.Success)
                        return match.Groups[1].Value;
                }
            }
            catch { }
            return "MAC_FALLBACK";
        }

        return "CROSS_FALLBACK";
    }

    [GeneratedRegex("\"IOPlatformUUID\" = \"([^\"]+)\"")]
    private static partial Regex UuidRegex();
}
