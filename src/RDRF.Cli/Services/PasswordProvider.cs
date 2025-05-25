using Spectre.Console;
using System.Text;

namespace RDRF.Cli.Services;

public static class PasswordProvider
{
    public static byte[] ReadInteractive(string prompt = "Password:")
    {
        var password = AnsiConsole.Prompt(
            new TextPrompt<string>(prompt).Secret());
        return Encoding.UTF8.GetBytes(password);
    }
}
