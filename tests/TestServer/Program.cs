var store = args.Length > 0
    ? args[0]
    : Path.Combine(Path.GetTempPath(), "rdrf_test_server");
Directory.CreateDirectory(store);

Console.Error.WriteLine($"TestServer: store={store}");

var app = WebApplication.Create(args);

app.MapGet("/health", () => "OK");

app.MapGet("/{**path}", (string path) =>
{
    var file = Path.Combine(store, path);
    if (!File.Exists(file))
        return Results.NotFound();

    var bytes = File.ReadAllBytes(file);
    var sha = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes)).ToLowerInvariant();
    return Results.Json(new
    {
        name = Path.GetFileName(path),
        path = path,
        sha,
        content = Convert.ToBase64String(bytes),
        encoding = "base64",
        size = bytes.Length
    });
});

app.MapPut("/{**path}", async (string path, HttpRequest req) =>
{
    var file = Path.Combine(store, path);
    Directory.CreateDirectory(Path.GetDirectoryName(file)!);
    using var ms = new MemoryStream();
    await req.Body.CopyToAsync(ms);
    await File.WriteAllBytesAsync(file, ms.ToArray());
    return Results.Ok(new { content = Convert.ToBase64String(ms.ToArray()) });
});

app.MapDelete("/{**path}", (string path) =>
{
    var file = Path.Combine(store, path);
    if (File.Exists(file)) File.Delete(file);
    return Results.Ok();
});

AppDomain.CurrentDomain.ProcessExit += (_, _) => {
    try { System.IO.Directory.Delete(store, recursive: true); } catch { }
    Console.Error.WriteLine("TestServer: cleaned " + store);
};
app.Run("http://localhost:5200");
