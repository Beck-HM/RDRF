using Spectre.Console;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace RDRF.Cli.Services;

public static class PasswordProvider
{
    public static byte[] ReadInteractive(string prompt = "Password:")
    {
        if (!Console.IsInputRedirected)
        {
            string pw = AnsiConsole.Prompt(
                new TextPrompt<string>(prompt).Secret());
            byte[] result = Encoding.UTF8.GetBytes(pw);
            ZeroString(pw);
            return result;
        }
        AnsiConsole.MarkupLine("[red]Error: stdin is redirected. Use -password <plaintext> to provide the password (INSECURE).[/]");
        return [];
    }

    private static unsafe void ZeroString(string s)
    {
        if (string.IsNullOrEmpty(s)) return;
        fixed (char* p = s)
        {
            for (int i = 0; i < s.Length; i++)
                p[i] = '\0';
        }
    }
}







