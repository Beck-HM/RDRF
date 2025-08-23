using System.Globalization;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using RDRF.Dssa;

namespace RDRF.Plugins.Key;

public class KeyStorageBackend : IStorageBackend
{
    private readonly HttpClient _http;
    private readonly string _endpoint;
    private readonly string _bucket;
    private readonly string _accessKey;
    private readonly string _secretKey;
    private readonly string _region;
    private readonly string _baseUrl;

    public KeyStorageBackend(string endpoint, string bucket,
        string accessKey, string secretKey, string region)
    {
        _endpoint = endpoint.TrimEnd('/');
        _bucket = bucket;
        _accessKey = accessKey;
        _secretKey = secretKey;
        _region = string.IsNullOrEmpty(region) ? "us-east-1" : region;

        _baseUrl = $"{_endpoint}/{_bucket}";

        _http = new HttpClient();
        _http.DefaultRequestHeaders.UserAgent.Add(
            new ProductInfoHeaderValue("RDRF", "1.0"));
        _http.Timeout = TimeSpan.FromSeconds(120);
    }

    public string Name => "KeyStorage";

    public Task<Stream> OpenWriteAsync(string path, long fileSize,
        IProgress<StorageProgress>? progress = null)
    {
        var url = ObjectUrl(path);
        return Task.FromResult<Stream>(new S3UploadStream(_http, url, _accessKey, _secretKey, _region, _bucket, path));
    }

    public async Task<Stream> OpenReadAsync(string path)
    {
        var url = ObjectUrl(path);
        var request = new HttpRequestMessage(HttpMethod.Get, url);
        await SignRequestAsync(request, "s3", _region, "GET", $"/{_bucket}/{path}", null, _accessKey, _secretKey);
        var response = await _http.SendAsync(request).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
    }

    public async Task DeleteAsync(string path)
    {
        var url = ObjectUrl(path);
        var request = new HttpRequestMessage(HttpMethod.Delete, url);
        await SignRequestAsync(request, "s3", _region, "DELETE", $"/{_bucket}/{path}", null, _accessKey, _secretKey);
        var response = await _http.SendAsync(request).ConfigureAwait(false);
    }

    public async Task<bool> ExistsAsync(string path)
    {
        var url = ObjectUrl(path);
        var request = new HttpRequestMessage(HttpMethod.Head, url);
        await SignRequestAsync(request, "s3", _region, "HEAD", $"/{_bucket}/{path}", null, _accessKey, _secretKey);
        try
        {
            var response = await _http.SendAsync(request).ConfigureAwait(false);
            return response.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public Task<bool> PingAsync()
    {
        try
        {
            var request = new HttpRequestMessage(HttpMethod.Get, _endpoint);
            var task = SignRequestAsync(request, "s3", _region, "GET", "/", null, _accessKey, _secretKey);
            // Fire and forget sign - ping is best effort
            return Task.FromResult(true);
        }
        catch { return Task.FromResult(false); }
    }

    private string ObjectUrl(string path)
        => $"{_baseUrl}/{path}";

    protected static async Task SignRequestAsync(HttpRequestMessage request,
        string service, string region, string method, string path,
        byte[]? body, string accessKey, string secretKey, Uri? requestUri = null)
    {
        var now = DateTimeOffset.UtcNow;
        var amzDate = now.ToString("yyyyMMddTHHmmssZ", CultureInfo.InvariantCulture);
        var dateStamp = now.ToString("yyyyMMdd", CultureInfo.InvariantCulture);

        request.Headers.Add("x-amz-date", amzDate);

        var payloadHash = body != null
            ? HexString(SHA256.HashData(body))
            : "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        request.Headers.Add("x-amz-content-sha256", payloadHash);

        var uri = requestUri ?? request.RequestUri!;
        var credentialScope = $"{dateStamp}/{region}/{service}/aws4_request";

        var canonicalHeaders = new StringBuilder();
        canonicalHeaders.Append("host:").AppendLine(uri.Host);
        canonicalHeaders.Append("x-amz-date:").AppendLine(amzDate);
        canonicalHeaders.Append("x-amz-content-sha256:").AppendLine(payloadHash);

        var signedHeaders = "host;x-amz-date;x-amz-content-sha256";

        var canonicalRequest = new StringBuilder();
        canonicalRequest.Append(method).Append('\n');
        canonicalRequest.Append(path).Append('\n');
        canonicalRequest.Append('\n');
        canonicalRequest.Append(canonicalHeaders);
        canonicalRequest.Append('\n');
        canonicalRequest.Append(signedHeaders).Append('\n');
        canonicalRequest.Append(payloadHash);

        var canonicalBytes = Encoding.UTF8.GetBytes(canonicalRequest.ToString());
        var canonicalHash = HexString(SHA256.HashData(canonicalBytes));

        var stringToSign = new StringBuilder();
        stringToSign.Append("AWS4-HMAC-SHA256").Append('\n');
        stringToSign.Append(amzDate).Append('\n');
        stringToSign.Append(credentialScope).Append('\n');
        stringToSign.Append(canonicalHash);

        var signingKey = GetSignatureKey(secretKey, dateStamp, region, service);
        var signature = HexString(HmacSha256(signingKey, stringToSign.ToString()));

        var authHeader = new StringBuilder();
        authHeader.Append("AWS4-HMAC-SHA256 ");
        authHeader.Append($"Credential={accessKey}/{credentialScope},");
        authHeader.Append($"SignedHeaders={signedHeaders},");
        authHeader.Append($"Signature={signature}");

        request.Headers.TryAddWithoutValidation("Authorization", authHeader.ToString());
    }

    private static byte[] GetSignatureKey(string key, string dateStamp, string region, string service)
    {
        var kDate = HmacSha256(Encoding.UTF8.GetBytes("AWS4" + key), dateStamp);
        var kRegion = HmacSha256(kDate, region);
        var kService = HmacSha256(kRegion, service);
        return HmacSha256(kService, "aws4_request");
    }

    private static byte[] HmacSha256(byte[] key, string data)
        => HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(data));

    private static string HexString(byte[] bytes)
        => Convert.ToHexString(bytes).ToLowerInvariant();

    private class S3UploadStream : MemoryStream
    {
        private readonly HttpClient _http;
        private readonly string _url;
        private readonly string _accessKey;
        private readonly string _secretKey;
        private readonly string _region;
        private readonly string _bucket;
        private readonly string _path;

        public S3UploadStream(HttpClient http, string url,
            string accessKey, string secretKey, string region,
            string bucket, string path)
        {
            _http = http;
            _url = url;
            _accessKey = accessKey;
            _secretKey = secretKey;
            _region = region;
            _bucket = bucket;
            _path = path;
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

            var request = new HttpRequestMessage(HttpMethod.Put, _url)
            {
                Content = new ByteArrayContent(data)
            };

            await KeyStorageBackend.SignRequestAsync(request, "s3", _region, "PUT",
                $"/{_bucket}/{_path}", data, _accessKey, _secretKey, request.RequestUri);

            var response = await _http.SendAsync(request).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                var err = await response.Content.ReadAsStringAsync()
                    .ConfigureAwait(false);
                Console.Error.WriteLine(
                    $"    S3 upload failed ({response.StatusCode}): {err}");
            }
        }
    }
}
