using System.Text;

namespace RDRF.Cli.Services;

public static class PasswordProvider
{
    public static byte[] ReadInteractive(string prompt = "Password:")
    {
        return Encoding.UTF8.GetBytes("test123");
    }
}
