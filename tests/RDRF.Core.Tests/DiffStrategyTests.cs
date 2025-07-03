using RDRF.Core.Diff;
using RDRF.Core.Diff.Strategies;
using Xunit;
using Xunit.Abstractions;

namespace RDRF.Core.Tests;

public class DiffStrategyTests
{
    private readonly ITestOutputHelper _output;

    public DiffStrategyTests(ITestOutputHelper output) => _output = output;

    // ── JsonDiffStrategy ──

    [Fact]
    public void Json_MatchScore_JsonExtension()
    {
        var s = new JsonDiffStrategy();
        double score = s.MatchScore("config.json", "{\"a\":1}"u8);
        Assert.Equal(1.0, score);
    }

    [Fact]
    public void Json_MatchScore_Braces()
    {
        var s = new JsonDiffStrategy();
        double score = s.MatchScore(null, "  {\"a\":1}"u8);
        Assert.Equal(0.95, score);
    }

    [Fact]
    public void Json_MatchScore_NonJson()
    {
        var s = new JsonDiffStrategy();
        double score = s.MatchScore("file.txt", "hello world"u8);
        Assert.Equal(0, score);
    }

    [Fact]
    public void Json_ComputeDiff_ChangedValue()
    {
        var s = new JsonDiffStrategy();
        byte[] oldJson = """{"host": "localhost", "port": 5432}"""u8.ToArray();
        byte[] newJson = """{"host": "db.example.com", "port": 5432}"""u8.ToArray();

        var result = s.ComputeDiff(oldJson, newJson, "config.json");

        Assert.Contains("$.host", result.HumanDiff);
        Assert.Contains("localhost", result.HumanDiff);
        Assert.Contains("db.example.com", result.HumanDiff);
        Assert.DoesNotContain("$.port", result.HumanDiff);
        _output.WriteLine($"JSON diff:\n{result.HumanDiff}");
    }

    [Fact]
    public void Json_ComputeDiff_AddedProperty()
    {
        var s = new JsonDiffStrategy();
        byte[] oldJson = """{"a": 1}"""u8.ToArray();
        byte[] newJson = """{"a": 1, "b": 2}"""u8.ToArray();

        var result = s.ComputeDiff(oldJson, newJson, "test.json");

        Assert.Contains("$.b", result.HumanDiff);
        Assert.Contains("(added)", result.HumanDiff);
    }

    [Fact]
    public void Json_ComputeDiff_RemovedProperty()
    {
        var s = new JsonDiffStrategy();
        byte[] oldJson = """{"a": 1, "b": 2}"""u8.ToArray();
        byte[] newJson = """{"a": 1}"""u8.ToArray();

        var result = s.ComputeDiff(oldJson, newJson, "test.json");

        Assert.Contains("$.b", result.HumanDiff);
        Assert.Contains("(removed)", result.HumanDiff);
    }

    [Fact]
    public void Json_ComputeDiff_NestedObject()
    {
        var s = new JsonDiffStrategy();
        byte[] oldJson = """{"db": {"host": "local", "port": 1}}"""u8.ToArray();
        byte[] newJson = """{"db": {"host": "remote", "port": 2}}"""u8.ToArray();

        var result = s.ComputeDiff(oldJson, newJson, "nested.json");

        Assert.Contains("$.db.host", result.HumanDiff);
        Assert.Contains("$.db.port", result.HumanDiff);
    }

    [Fact]
    public void Json_ComputeDiff_ArrayChanged()
    {
        var s = new JsonDiffStrategy();
        byte[] oldJson = """{"items": [1, 2, 3]}"""u8.ToArray();
        byte[] newJson = """{"items": [1, 4, 3, 5]}"""u8.ToArray();

        var result = s.ComputeDiff(oldJson, newJson, "array.json");

        Assert.Contains("$.items[1]", result.HumanDiff);
        Assert.Contains("$.items[3]", result.HumanDiff);
    }

    [Fact]
    public void Json_ComputeDiff_Identical_Empty()
    {
        var s = new JsonDiffStrategy();
        byte[] json = """{"a": 1}"""u8.ToArray();

        var result = s.ComputeDiff(json, json, "same.json");

        Assert.Empty(result.Lines);
    }

    [Fact]
    public void Json_ComputeDiff_ValueTypeChanged()
    {
        var s = new JsonDiffStrategy();
        byte[] oldJson = """{"x": "string"}"""u8.ToArray();
        byte[] newJson = """{"x": 42}"""u8.ToArray();

        var result = s.ComputeDiff(oldJson, newJson, "typechange.json");

        Assert.Contains("$.x", result.HumanDiff);
        Assert.Contains("String", result.HumanDiff);
        Assert.Contains("Number", result.HumanDiff);
    }

    // ── IniDiffStrategy ──

    [Fact]
    public void Ini_MatchScore_IniExtension()
    {
        var s = new IniDiffStrategy();
        double score = s.MatchScore("settings.ini", "[section]"u8);
        Assert.Equal(1.0, score);
    }

    [Fact]
    public void Ini_MatchScore_CfgExtension()
    {
        var s = new IniDiffStrategy();
        double score = s.MatchScore("app.cfg", "[section]"u8);
        Assert.Equal(1.0, score);
    }

    [Fact]
    public void Ini_MatchScore_ContentDetect()
    {
        var s = new IniDiffStrategy();
        double score = s.MatchScore(null, "[database]\nhost=localhost"u8);
        Assert.True(score >= 0.8);
    }

    [Fact]
    public void Ini_MatchScore_NonIni()
    {
        var s = new IniDiffStrategy();
        double score = s.MatchScore("readme.txt", "hello"u8);
        Assert.Equal(0, score);
    }

    [Fact]
    public void Ini_ComputeDiff_ChangedKey()
    {
        var s = new IniDiffStrategy();
        byte[] oldIni = "[db]\nhost=local\nport=5432"u8.ToArray();
        byte[] newIni = "[db]\nhost=remote\nport=5432"u8.ToArray();

        var result = s.ComputeDiff(oldIni, newIni, "db.ini");

        Assert.Contains("host", result.HumanDiff);
        Assert.Contains("local", result.HumanDiff);
        Assert.Contains("remote", result.HumanDiff);
        Assert.DoesNotContain("port", result.HumanDiff);
        _output.WriteLine($"INI diff:\n{result.HumanDiff}");
    }

    [Fact]
    public void Ini_ComputeDiff_SectionAdded()
    {
        var s = new IniDiffStrategy();
        byte[] oldIni = "[db]\nhost=local"u8.ToArray();
        byte[] newIni = "[db]\nhost=local\n[logging]\nlevel=debug"u8.ToArray();

        var result = s.ComputeDiff(oldIni, newIni, "app.ini");

        Assert.Contains("logging", result.HumanDiff);
        Assert.Contains("section added", result.HumanDiff);
    }

    [Fact]
    public void Ini_ComputeDiff_KeyAdded()
    {
        var s = new IniDiffStrategy();
        byte[] oldIni = "[db]\nhost=local"u8.ToArray();
        byte[] newIni = "[db]\nhost=local\nport=3306"u8.ToArray();

        var result = s.ComputeDiff(oldIni, newIni, "db.ini");

        Assert.Contains("port", result.HumanDiff);
        Assert.Contains("(added)", result.HumanDiff);
    }

    [Fact]
    public void Ini_ComputeDiff_KeyRemoved()
    {
        var s = new IniDiffStrategy();
        byte[] oldIni = "[db]\nhost=local\nport=3306"u8.ToArray();
        byte[] newIni = "[db]\nhost=local"u8.ToArray();

        var result = s.ComputeDiff(oldIni, newIni, "db.ini");

        Assert.Contains("port", result.HumanDiff);
        Assert.Contains("(removed)", result.HumanDiff);
    }

    [Fact]
    public void Ini_ComputeDiff_Identical_Empty()
    {
        var s = new IniDiffStrategy();
        byte[] ini = "[a]\nx=y"u8.ToArray();

        var result = s.ComputeDiff(ini, ini, "same.ini");

        Assert.Empty(result.Lines);
    }

    [Fact]
    public void Ini_ComputeDiff_CommentIgnored()
    {
        var s = new IniDiffStrategy();
        byte[] oldIni = "[a]\n; comment\nx=1"u8.ToArray();
        byte[] newIni = "[a]\n# another comment\nx=1"u8.ToArray();

        var result = s.ComputeDiff(oldIni, newIni, "conf.ini");

        Assert.Empty(result.Lines);
    }
}
