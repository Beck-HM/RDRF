using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using RDRF.Core.Dssa;

namespace RDRF.Plugins.Rest;

public class RestStorageBackend : IStorageBackend
{
    private readonly HttpClient _http;
    private readonly string _baseUrl;

    public RestStorageBackend(string apiUrl, string token)
    {
        _baseUrl = apiUrl.TrimEnd('/');

        System.Net.ServicePointManager.SecurityProtocol =
            System.Net.SecurityProtocolType.Tls12 |
            System.Net.SecurityProtocolType.Tls13;

        var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
            SslOptions = new System.Net.Security.SslClientAuthenticationOptions
            {
                EnabledSslProtocols =
                    System.Security.Authentication.SslProtocols.Tls12
            }
        };
        _http = new HttpClient(handler);
        _http.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", token);
        _http.DefaultRequestHeaders.UserAgent.Add(
            new ProductInfoHeaderValue("RDRF", "1.0"));
        _http.DefaultRequestHeaders.Accept.Add(
            new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
        _http.Timeout = TimeSpan.FromSeconds(120);
    }

    public string Name => "RestStorage";

    public Task<Stream> OpenWriteAsync(string path, long fileSize,
        IProgress<StorageProgress>? progress = null)
    {
        return Task.FromResult<Stream>(
            new GitHubUploadStream(_http, _baseUrl, path));
    }

    public async Task<Stream> OpenReadAsync(string path)
    {
        var response = await _http.GetAsync(UrlFor(path))
            .ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        var json = await response.Content.ReadAsStringAsync()
            .ConfigureAwait(false);
        var doc = JsonDocument.Parse(json);
        var content = doc.RootElement.GetProperty("content").GetString()!;
        var clean = content.Replace("\n", "").Replace("\r", "");
        var bytes = Convert.FromBase64String(clean);
        return new MemoryStream(bytes);
    }

    public async Task DeleteAsync(string path)
    {
        var url = UrlFor(path);
        var getResp = await _http.GetAsync(url).ConfigureAwait(false);
        if (!getResp.IsSuccessStatusCode) return;

        var json = await getResp.Content.ReadAsStringAsync()
            .ConfigureAwait(false);
        var doc = JsonDocument.Parse(json);
        var sha = doc.RootElement.GetProperty("sha").GetString()!;

        var body = JsonSerializer.Serialize(new
        {
            message = "rdrf delete",
            sha
        });
        using var req = new HttpRequestMessage(HttpMethod.Delete, url)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json")
        };
        await _http.SendAsync(req).ConfigureAwait(false);
    }

    public async Task<bool> ExistsAsync(string path)
    {
        try
        {
            var resp = await _http.GetAsync(UrlFor(path))
                .ConfigureAwait(false);
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> PingAsync()
    {
        try
        {
            var resp = await _http
                .GetAsync("https://api.github.com/user")
                .ConfigureAwait(false);
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    private string UrlFor(string path)
        => $"{_baseUrl}/{path.TrimStart('/')}";

    private class GitHubUploadStream : MemoryStream
    {
        private readonly HttpClient _http;
        private readonly string _url;

        public GitHubUploadStream(HttpClient http, string baseUrl, string path)
        {
            _http = http;
            _url = $"{baseUrl.TrimEnd('/')}/{path.TrimStart('/')}";
        }

        protected override void Dispose(bool disposing)
        {
            if (!disposing) return;
            UploadAsync().GetAwaiter().GetResult();
            base.Dispose(disposing);
        }

        public override async ValueTask DisposeAsync()
        {
            await UploadAsync().ConfigureAwait(false);
            await base.DisposeAsync().ConfigureAwait(false);
        }

        private async Task UploadAsync()
        {
            var data = ToArray();
            if (data.Length == 0) return;

            var b64 = Convert.ToBase64String(data);

            string? sha = null;
            try
            {
                var getResp = await _http.GetAsync(_url).ConfigureAwait(false);
                if (getResp.IsSuccessStatusCode)
                {
                    var json = await getResp.Content.ReadAsStringAsync()
                        .ConfigureAwait(false);
                    var doc = JsonDocument.Parse(json);
                    sha = doc.RootElement.GetProperty("sha").GetString();
                }
            }
            catch { }

            var payload = new Dictionary<string, object>
            {
                ["message"] = "rdrf push",
                ["content"] = b64
            };
            if (sha != null)
                payload["sha"] = sha;

            var response = await _http.PutAsync(_url,
                new StringContent(
                    JsonSerializer.Serialize(payload),
                    Encoding.UTF8, "application/json"))
                .ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                var err = await response.Content.ReadAsStringAsync()
                    .ConfigureAwait(false);
                Console.Error.WriteLine(
                    $"    GitHub upload failed ({response.StatusCode}): {err}");
            }
        }
    }
}
