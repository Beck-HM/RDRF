using RDRF.Storage;

namespace RDRF.Deploy.Pull;

public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        var (indexPath, pwdArg, versionArg) = DeployHelper.ParsePullArgs(args);
        if (string.IsNullOrEmpty(indexPath)) return 1;
        byte[] password = DeployHelper.ResolvePassword(pwdArg);
        try { return await PullService.Run(indexPath, password, versionArg); }
        finally { if (password.Length > 0) System.Security.Cryptography.CryptographicOperations.ZeroMemory(password); }
    }
}
