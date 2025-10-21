using Spectre.Console;
using System.Security.Cryptography;
using System.Text;

namespace RDRF.Cli.Services;

public static class PasswordProvider
{
    public static byte[] ReadInteractive(string prompt = "Password:")
    {
        if (!Console.IsInputRedirected)
        {
            var pw = AnsiConsole.Prompt(
                new TextPrompt<string>(prompt).Secret());
            byte[] result = Encoding.UTF8.GetBytes(pw);
            // string is immutable and cannot be zeroed, but we minimize its lifetime
            return result;
        }
        AnsiConsole.MarkupLine("[red]Error: stdin is redirected. Use -password <plaintext> to provide the password (INSECURE).[/]");
        return [];
    }
}
