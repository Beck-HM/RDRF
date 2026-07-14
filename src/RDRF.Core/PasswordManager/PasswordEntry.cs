namespace RDRF.Core.PasswordManager;

public class PasswordEntry
{
    public string Key { get; set; } = "";
    public string Value { get; set; } = "";
    public long CreatedAt { get; set; }
}

public class BackupEntry
{
    public string Key { get; set; } = "";
    public string IndexHash { get; set; } = "";
    public long CreatedAt { get; set; }
}
