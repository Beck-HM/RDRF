using System.Security.Cryptography;
using System.CommandLine;

namespace RDRF.Cli.Services;

public static class PasswordOptions
{
    private const string PasswordOptName = "password";
    private const string PasswordFileOptName = "password-file";

    public static void AddToCommand(Command command)
    {
        var passwordOpt = new Option<string?>("-password")
        {
            Description = "Password as plain text (INSECURE: visible in process list; omit for secure prompt)"
        };
        var passwordFileOpt = new Option<FileInfo?>("--password-file")
        {
            Description = "Read password from file (first line only, secure alternative to -password)"
        };
        command.Add(passwordOpt);
        command.Add(passwordFileOpt);
    }

    public static byte[] ResolveFrom(ParseResult parseResult)
    {
        var filePwd = parseResult.GetValue<FileInfo?>(PasswordFileOptName);
        if (filePwd != null && filePwd.Exists)
        {
            string content = File.ReadAllText(filePwd.FullName).Trim();
            if (string.IsNullOrEmpty(content))
                throw new ArgumentException("Password file is empty.");
            return System.Text.Encoding.UTF8.GetBytes(content);
        }

        var plainPwd = parseResult.GetValue<string?>(PasswordOptName);
        if (plainPwd != null)
            return System.Text.Encoding.UTF8.GetBytes(plainPwd);

        return PasswordProvider.ReadInteractive();
    }
}
