using Spectre.Console;
using System.Text;

namespace RDRF.Cli.Services;

public static class PasswordProvider
{
    public static byte[] ReadInteractive(string prompt = "Password:")
    {
        string? env = Environment.GetEnvironmentVariable("RDRF_PASSWORD");
        if (env != null)
            return Encoding.UTF8.GetBytes(env);
        var password = AnsiConsole.Prompt(
            new TextPrompt<string>(prompt).Secret());
        return Encoding.UTF8.GetBytes(password);
    }
}
