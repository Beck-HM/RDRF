using RDRF.Storage;

namespace RDRF.Deploy.Push;

public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        var (indexPath, pwdArg) = DeployHelper.ParsePushArgs(args);
        if (string.IsNullOrEmpty(indexPath)) return 1;
        byte[] password = DeployHelper.ResolvePassword(pwdArg);
        try { return await PushService.Run(indexPath, password); }
        finally { if (password.Length > 0) System.Security.Cryptography.CryptographicOperations.ZeroMemory(password); }
    }
}
