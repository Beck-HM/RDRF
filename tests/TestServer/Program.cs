var store = Path.Combine(Path.GetTempPath(), "rdrf_test_server");
Directory.CreateDirectory(store);

var app = WebApplication.Create(args);

app.MapGet("/health", () => "OK");

app.MapGet("/{**path}", (string path) =>
{
    var file = Path.Combine(store, path);
    return File.Exists(file)
        ? Results.File(File.ReadAllBytes(file), "application/octet-stream")
        : Results.NotFound();
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

app.Run("http://localhost:5200");
