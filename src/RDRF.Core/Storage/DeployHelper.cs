using System.Text;

namespace RDRF.Dssa;

public static class DeployHelper
{
    public static (string IndexPath, byte[]? PasswordArg) ParsePushArgs(string[] args)
    {
        if (args.Length < 1 || args[0] is "-h" or "--help")
        {
            Console.Error.WriteLine("Usage: rdrf-push <indexFile> [-p password]");
            return (string.Empty, null);
        }

        var indexPath = Path.GetFullPath(args[0]);
        if (!File.Exists(indexPath))
        {
            Console.Error.WriteLine($"Error: index file not found: {indexPath}");
            return (string.Empty, null);
        }

        string? pwdArg = null;
        for (int i = 1; i < args.Length; i++)
            if (args[i] == "-p" && i + 1 < args.Length)
                pwdArg = args[++i];

        return (indexPath, pwdArg != null ? Encoding.UTF8.GetBytes(pwdArg) : null);
    }

    public static (string IndexPath, byte[]? PasswordArg, string? VersionArg) ParsePullArgs(string[] args)
    {
        if (args.Length < 1 || args[0] is "-h" or "--help")
        {
            Console.Error.WriteLine("Usage: rdrf-pull <indexFile> [-p password] [-v version|list]");
            return (string.Empty, null, null);
        }

        var indexPath = Path.GetFullPath(args[0]);
        if (!File.Exists(indexPath))
        {
            Console.Error.WriteLine($"Error: index file not found: {indexPath}");
            return (string.Empty, null, null);
        }

        string? pwdArg = null;
        string? versionArg = null;
        for (int i = 1; i < args.Length; i++)
        {
            if (args[i] == "-p" && i + 1 < args.Length)
                pwdArg = args[++i];
            else if (args[i] == "-v" && i + 1 < args.Length)
                versionArg = args[++i];
        }

        return (indexPath, pwdArg != null ? Encoding.UTF8.GetBytes(pwdArg) : null, versionArg);
    }

    public static byte[] ReadPasswordInteractive()
    {
        Console.Error.Write("Password: ");
        var sb = new StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(true);
            if (key.Key == ConsoleKey.Enter)
            {
                Console.Error.WriteLine();
                break;
            }
            if (key.Key == ConsoleKey.Backspace && sb.Length > 0)
            {
                sb.Length--;
            }
            else if (key.KeyChar is >= ' ' and <= '~')
            {
                sb.Append(key.KeyChar);
            }
        }
        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    public static byte[] ResolvePassword(byte[]? arg)
        => arg ?? ReadPasswordInteractive();
}
