using System.Net;
using System.Text;
using RDRF.Plugins.Key;
using Xunit;

namespace RDRF.Core.Tests;

public class KeyStorageBackendTests : IDisposable
{
    private readonly HttpListener _server;
    private readonly Thread _serverThread;
    private readonly string _baseUrl;
    private readonly Dictionary<string, byte[]> _store = new();
    private readonly object _lock = new();
    private volatile bool _running;

    public KeyStorageBackendTests()
    {
        _baseUrl = "http://127.0.0.1:18456";
        _server = new HttpListener();
        _server.Prefixes.Add(_baseUrl + "/");
        _server.Start();
        _running = true;
        _serverThread = new Thread(HandleRequests);
        _serverThread.Start();
    }

    private void HandleRequests()
    {
        while (_running)
        {
            try
            {
                var ctx = _server.GetContext();
                Task.Run(() => ProcessRequest(ctx));
            }
            catch { break; }
        }
    }

    private void ProcessRequest(HttpListenerContext ctx)
    {
        try
        {
            string method = ctx.Request.HttpMethod;
            string path = ctx.Request.Url!.AbsolutePath.TrimStart('/');

            switch (method)
            {
                case "PUT":
                    using (var ms = new MemoryStream())
                    {
                        ctx.Request.InputStream.CopyTo(ms);
                        lock (_lock) _store[path] = ms.ToArray();
                    }
                    ctx.Response.StatusCode = 200;
                    ctx.Response.Close();
                    break;

                case "GET":
                    lock (_lock)
                    {
                        if (_store.TryGetValue(path, out var data))
                        {
                            ctx.Response.ContentType = "application/octet-stream";
                            ctx.Response.ContentLength64 = data.Length;
                            ctx.Response.OutputStream.Write(data);
                        }
                        else
                        {
                            ctx.Response.StatusCode = 404;
                        }
                    }
                    ctx.Response.Close();
                    break;

                case "HEAD":
                    lock (_lock)
                    {
                        ctx.Response.StatusCode = _store.ContainsKey(path) ? 200 : 404;
                    }
                    ctx.Response.Close();
                    break;

                case "DELETE":
                    lock (_lock) _store.Remove(path);
                    ctx.Response.StatusCode = 204;
                    ctx.Response.Close();
                    break;

                default:
                    ctx.Response.StatusCode = 405;
                    ctx.Response.Close();
                    break;
            }
        }
        catch { }
    }

    [Fact]
    public async Task WriteAndRead_RoundTrip()
    {
        var backend = new KeyStorageBackend(_baseUrl, "test-bucket", "AKID", "secret", "");
        var data = new byte[] { 1, 2, 3, 4, 5 };

        await using (var stream = await backend.OpenWriteAsync("test.bin", data.Length))
            await stream.WriteAsync(data);

        Assert.True(await backend.ExistsAsync("test.bin"));

        await using (var stream = await backend.OpenReadAsync("test.bin"))
        {
            var buf = new byte[data.Length];
            int read = await stream.ReadAsync(buf);
            Assert.Equal(data.Length, read);
            Assert.Equal(data, buf);
        }
    }

    [Fact]
    public async Task Delete_RemovesFile()
    {
        var backend = new KeyStorageBackend(_baseUrl, "test-bucket", "AKID", "secret", "");
        await using (var stream = await backend.OpenWriteAsync("del_test.bin", 4))
            await stream.WriteAsync(new byte[] { 1, 2, 3, 4 });

        Assert.True(await backend.ExistsAsync("del_test.bin"));
        await backend.DeleteAsync("del_test.bin");
        Assert.False(await backend.ExistsAsync("del_test.bin"));
    }

    [Fact]
    public async Task OpenRead_Nonexistent_Throws()
    {
        var backend = new KeyStorageBackend(_baseUrl, "test-bucket", "AKID", "secret", "");
        await Assert.ThrowsAsync<HttpRequestException>(() =>
        {
            var stream = backend.OpenReadAsync("no_such_file.bin");
            return stream;
        });
    }

    public void Dispose()
    {
        _running = false;
        try { _server.Stop(); } catch { }
    }
}
