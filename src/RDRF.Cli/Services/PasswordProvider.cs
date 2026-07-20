using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace RDRF.Cli.Services;

public static class PasswordProvider
{
    public static byte[] ReadInteractive(string prompt = "Password:")
    {
        if (Console.IsInputRedirected)
        {
            Console.Error.WriteLine("Error: stdin is redirected. Use -password <plaintext> to provide the password.");
            return [];
        }

        Console.Write(prompt);
        var buf = new char[128];
        int len = 0;
        while (len < buf.Length)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter) break;
            if (key.Key == ConsoleKey.Backspace && len > 0) { len--; continue; }
            if (!char.IsControl(key.KeyChar)) buf[len++] = key.KeyChar;
        }
        Console.WriteLine();

        if (len == 0) return [];

        var result = new byte[Encoding.UTF8.GetMaxByteCount(len)];
        int bytesWritten = Encoding.UTF8.GetBytes(buf, 0, len, result, 0);
        CryptographicOperations.ZeroMemory(MemoryMarshal.Cast<char, byte>(buf.AsSpan(0, len)));
        if (bytesWritten < result.Length)
        {
            var trimmed = new byte[bytesWritten];
            Buffer.BlockCopy(result, 0, trimmed, 0, bytesWritten);
            CryptographicOperations.ZeroMemory(result);
            return trimmed;
        }
        return result;
    }
}
