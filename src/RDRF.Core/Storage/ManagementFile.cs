using Microsoft.Data.Sqlite;

namespace RDRF.Core.Dssa;

public class ManagementFile
{
    private readonly string _dbPath;

    public ManagementFile(string? directoryPath = null)
    {
        directoryPath ??= Path.Combine(Directory.GetCurrentDirectory(), ".rdrf");
        _dbPath = Path.Combine(directoryPath, ".rdrf_management");
        Directory.CreateDirectory(directoryPath);
        Initialize();
    }

    private void Initialize()
    {
        using var conn = CreateConnection();
        conn.Open();

        using (var walCmd = conn.CreateCommand())
        {
            walCmd.CommandText = "PRAGMA journal_mode=WAL;";
            walCmd.ExecuteNonQuery();
        }

        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            CREATE TABLE IF NOT EXISTS remotes (
                name TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                config_json TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS projects (
                fingerprint TEXT PRIMARY KEY,
                original_name TEXT,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS versions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint TEXT NOT NULL REFERENCES projects(fingerprint),
                version_number INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS fragment_locations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint TEXT NOT NULL,
                version_number INTEGER NOT NULL,
                fragment_index INTEGER NOT NULL,
                content_type TEXT NOT NULL DEFAULT 'fragment',
                backend_name TEXT NOT NULL,
                remote_path TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                file_hash TEXT,
                note TEXT,
                uploaded_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_fl_lookup
                ON fragment_locations(fingerprint, version_number);
        ";
        cmd.ExecuteNonQuery();
    }

    public void RecordRemote(string name, string type,
        Dictionary<string, string> config)
    {
        using var conn = CreateConnection();
        conn.Open();

        var json = System.Text.Json.JsonSerializer.Serialize(config);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            INSERT OR REPLACE INTO remotes (name, type, config_json, created_at)
            VALUES ($name, $type, $json, $now)";
        cmd.Parameters.AddWithValue("$name", name);
        cmd.Parameters.AddWithValue("$type", type);
        cmd.Parameters.AddWithValue("$json", json);
        cmd.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        cmd.ExecuteNonQuery();
    }

    public RemoteConfig? GetRemote(string name)
    {
        using var conn = CreateConnection();
        conn.Open();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT type, config_json FROM remotes WHERE name = $name";
        cmd.Parameters.AddWithValue("$name", name);

        using var reader = cmd.ExecuteReader();
        if (!reader.Read()) return null;

        var json = reader.GetString(1);
        var config = System.Text.Json.JsonSerializer
            .Deserialize<Dictionary<string, string>>(json)
            ?? new Dictionary<string, string>();

        return new RemoteConfig
        {
            Name = name,
            Type = reader.GetString(0),
            Config = config,
        };
    }

    public List<RemoteConfig> ListRemotes()
    {
        var results = new List<RemoteConfig>();
        using var conn = CreateConnection();
        conn.Open();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT name, type, config_json FROM remotes ORDER BY name";

        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            var json = reader.GetString(2);
            var config = System.Text.Json.JsonSerializer
                .Deserialize<Dictionary<string, string>>(json)
                ?? new Dictionary<string, string>();

            results.Add(new RemoteConfig
            {
                Name = reader.GetString(0),
                Type = reader.GetString(1),
                Config = config,
            });
        }
        return results;
    }

    public void DeleteRemote(string name)
    {
        using var conn = CreateConnection();
        conn.Open();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM remotes WHERE name = $name";
        cmd.Parameters.AddWithValue("$name", name);
        cmd.ExecuteNonQuery();
    }

    private SqliteConnection CreateConnection()
        => new SqliteConnection($"Data Source={_dbPath}");

    public void RecordFragment(string fingerprint, int versionNumber,
        int fragmentIndex, string backendName, string remotePath,
        long fileSize, string? fileHash = null, string? note = null)
    {
        using var conn = CreateConnection();
        conn.Open();

        EnsureProject(conn, fingerprint, note);
        EnsureVersion(conn, fingerprint, versionNumber);

        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            INSERT INTO fragment_locations
                (fingerprint, version_number, fragment_index, content_type,
                 backend_name, remote_path, file_size, file_hash, note, uploaded_at)
            VALUES ($fp, $ver, $idx, $type, $backend, $path, $size, $hash, $note, $now)";
        cmd.Parameters.AddWithValue("$fp", fingerprint);
        cmd.Parameters.AddWithValue("$ver", versionNumber);
        cmd.Parameters.AddWithValue("$idx", fragmentIndex);
        cmd.Parameters.AddWithValue("$type", "fragment");
        cmd.Parameters.AddWithValue("$backend", backendName);
        cmd.Parameters.AddWithValue("$path", remotePath);
        cmd.Parameters.AddWithValue("$size", fileSize);
        cmd.Parameters.AddWithValue("$hash", (object?)fileHash ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$note", (object?)note ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        cmd.ExecuteNonQuery();
    }

    public void RecordRc(string fingerprint, int versionNumber,
        string backendName, string remotePath, long fileSize,
        string? fileHash = null, string? note = null)
    {
        using var conn = CreateConnection();
        conn.Open();

        EnsureProject(conn, fingerprint, note);
        EnsureVersion(conn, fingerprint, versionNumber);

        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            INSERT INTO fragment_locations
                (fingerprint, version_number, fragment_index, content_type,
                 backend_name, remote_path, file_size, file_hash, note, uploaded_at)
            VALUES ($fp, $ver, -1, 'rc', $backend, $path, $size, $hash, $note, $now)";
        cmd.Parameters.AddWithValue("$fp", fingerprint);
        cmd.Parameters.AddWithValue("$ver", versionNumber);
        cmd.Parameters.AddWithValue("$backend", backendName);
        cmd.Parameters.AddWithValue("$path", remotePath);
        cmd.Parameters.AddWithValue("$size", fileSize);
        cmd.Parameters.AddWithValue("$hash", (object?)fileHash ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$note", (object?)note ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        cmd.ExecuteNonQuery();
    }

    public List<FragmentLocation> Lookup(string fingerprint, int versionNumber)
    {
        var results = new List<FragmentLocation>();
        using var conn = CreateConnection();
        conn.Open();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            SELECT fragment_index, content_type, backend_name, remote_path,
                   file_size, file_hash, uploaded_at
            FROM fragment_locations
            WHERE fingerprint = $fp AND version_number = $ver
            ORDER BY fragment_index";
        cmd.Parameters.AddWithValue("$fp", fingerprint);
        cmd.Parameters.AddWithValue("$ver", versionNumber);

        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            results.Add(new FragmentLocation
            {
                FragmentIndex = reader.GetInt32(0),
                ContentType = reader.GetString(1),
                BackendName = reader.GetString(2),
                RemotePath = reader.GetString(3),
                FileSize = reader.GetInt64(4),
                FileHash = reader.IsDBNull(5) ? null : reader.GetString(5),
                UploadedAt = DateTimeOffset.FromUnixTimeSeconds(reader.GetInt64(6)),
            });
        }
        return results;
    }

    public FragmentLocation? LookupSingle(string fingerprint,
        int versionNumber, int fragmentIndex)
    {
        using var conn = CreateConnection();
        conn.Open();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            SELECT fragment_index, content_type, backend_name, remote_path,
                   file_size, file_hash, uploaded_at
            FROM fragment_locations
            WHERE fingerprint = $fp AND version_number = $ver
              AND fragment_index = $idx
            LIMIT 1";
        cmd.Parameters.AddWithValue("$fp", fingerprint);
        cmd.Parameters.AddWithValue("$ver", versionNumber);
        cmd.Parameters.AddWithValue("$idx", fragmentIndex);

        using var reader = cmd.ExecuteReader();
        if (reader.Read())
        {
            return new FragmentLocation
            {
                FragmentIndex = reader.GetInt32(0),
                ContentType = reader.GetString(1),
                BackendName = reader.GetString(2),
                RemotePath = reader.GetString(3),
                FileSize = reader.GetInt64(4),
                FileHash = reader.IsDBNull(5) ? null : reader.GetString(5),
                UploadedAt = DateTimeOffset.FromUnixTimeSeconds(reader.GetInt64(6)),
            };
        }
        return null;
    }

    public int DeleteVersion(string fingerprint, int versionNumber)
    {
        using var conn = CreateConnection();
        conn.Open();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            DELETE FROM fragment_locations
            WHERE fingerprint = $fp AND version_number = $ver";
        cmd.Parameters.AddWithValue("$fp", fingerprint);
        cmd.Parameters.AddWithValue("$ver", versionNumber);
        return cmd.ExecuteNonQuery();
    }

    public List<int> GetVersionNumbers(string fingerprint)
    {
        var versions = new List<int>();
        using var conn = CreateConnection();
        conn.Open();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            SELECT DISTINCT version_number
            FROM fragment_locations
            WHERE fingerprint = $fp
            ORDER BY version_number";
        cmd.Parameters.AddWithValue("$fp", fingerprint);

        using var reader = cmd.ExecuteReader();
        while (reader.Read())
            versions.Add(reader.GetInt32(0));
        return versions;
    }

    private void EnsureProject(SqliteConnection conn, string fingerprint, string? note)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            INSERT OR IGNORE INTO projects (fingerprint, original_name, created_at)
            VALUES ($fp, $name, $now)";
        cmd.Parameters.AddWithValue("$fp", fingerprint);
        cmd.Parameters.AddWithValue("$name", (object?)note ?? fingerprint);
        cmd.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        cmd.ExecuteNonQuery();
    }

    private void EnsureVersion(SqliteConnection conn, string fingerprint, int versionNumber)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            INSERT OR IGNORE INTO versions (fingerprint, version_number, created_at)
            VALUES ($fp, $ver, $now)";
        cmd.Parameters.AddWithValue("$fp", fingerprint);
        cmd.Parameters.AddWithValue("$ver", versionNumber);
        cmd.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        cmd.ExecuteNonQuery();
    }
}

public class FragmentLocation
{
    public int FragmentIndex { get; set; }
    public string ContentType { get; set; } = "fragment";
    public string BackendName { get; set; } = "";
    public string RemotePath { get; set; } = "";
    public long FileSize { get; set; }
    public string? FileHash { get; set; }
    public DateTimeOffset UploadedAt { get; set; }
}

public class RemoteConfig
{
    public string Name { get; set; } = "";
    public string Type { get; set; } = "";
    public Dictionary<string, string> Config { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}
