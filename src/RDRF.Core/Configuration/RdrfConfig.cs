namespace RDRF.Core.Configuration;

public static class RdrfConfig
{
    private static string? _customRoot;
    private static readonly string PointerPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        ".rdrfpointer");

    public static string RootDir
    {
        get
        {
            if (_customRoot != null) return _customRoot;
            string? pointer = TryReadPointer();
            if (pointer != null)
            {
                _customRoot = pointer;
                return _customRoot;
            }
            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                ".rdrf");
        }
    }

    public static string LogDir => Path.Combine(RootDir, "log");

    public static void Initialize()
    {
        string? pointer = TryReadPointer();
        if (pointer != null)
            _customRoot = pointer;
    }

    public static void MoveTo(string newPath)
    {
        string resolved = Path.GetFullPath(newPath);
        string oldDir = RootDir;
        bool sameVolume = Path.GetPathRoot(oldDir)?.Equals(
            Path.GetPathRoot(resolved), StringComparison.OrdinalIgnoreCase) == true;

        if (Directory.Exists(oldDir) && !string.Equals(oldDir, resolved, StringComparison.OrdinalIgnoreCase))
        {
            if (sameVolume)
            {
                Directory.Move(oldDir, resolved);
            }
            else
            {
                CopyDirectory(oldDir, resolved);
                Directory.Delete(oldDir, recursive: true);
            }
        }

        _customRoot = resolved;
        Directory.CreateDirectory(Path.GetDirectoryName(PointerPath)!);
        File.WriteAllText(PointerPath, resolved);
    }

    private static void CopyDirectory(string source, string dest)
    {
        Directory.CreateDirectory(dest);
        foreach (string file in Directory.GetFiles(source))
        {
            string destFile = Path.Combine(dest, Path.GetFileName(file));
            File.Copy(file, destFile, overwrite: true);
        }
        foreach (string dir in Directory.GetDirectories(source))
        {
            string destDir = Path.Combine(dest, Path.GetFileName(dir));
            CopyDirectory(dir, destDir);
        }
    }

    private static string? TryReadPointer()
    {
        try
        {
            if (File.Exists(PointerPath))
                return File.ReadAllText(PointerPath).Trim();
        }
        catch { }
        return null;
    }
}
