using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace RxPro.Core;

public sealed class ProfileException : Exception
{
    public ProfileException() : base("Некорректная S3-ссылка. Нужна ссылка RX-PRO из менеджера, а не обычная VLESS-ссылка панели.") { }
}

public sealed class S3Profile
{
    public string Name { get; }
    public Guid Uuid { get; }
    public string Host { get; }
    public string Encryption { get; }
    public string Endpoint { get; }
    public string Bucket { get; }
    public string Prefix { get; }
    public string AccessKey { get; }
    public string SecretKey { get; }
    public const string BootstrapAddress = "95.163.53.117"; // Same explicit snapshot as Android 1.6.0.
    private S3Profile(string name, Guid uuid, string host, string encryption, string endpoint,
                      string bucket, string prefix, string access, string secret)
    {
        Name = name; Uuid = uuid; Host = host; Encryption = encryption; Endpoint = endpoint;
        Bucket = bucket; Prefix = prefix; AccessKey = access; SecretKey = secret;
    }
    public override string ToString() => Name; // Never synthesize a diagnostic string containing keys.
    private static void Need(bool value) { if (!value) throw new ProfileException(); }
    public static string SafeName(string value) => string.IsNullOrWhiteSpace(value) || value.Length > 80 ||
        value.Any(char.IsControl) || new[] { "://", "%3a", "s3=", "secretkey", "accesskey", "github_pat_" }
        .Any(s => value.Contains(s, StringComparison.OrdinalIgnoreCase)) ? "VK S3" : value.Trim();
    public static S3Profile Parse(string input)
    {
        try
        {
            Need(input.Length <= 16384);
            input = input.Trim(); Need(!input.Any(char.IsControl));
            var uri = new Uri(input, UriKind.Absolute);
            Need(uri.Scheme == "vless" && uri.Port == 443 && uri.AbsolutePath is "" or "/");
            Need(!uri.UserInfo.Contains(':') && Guid.TryParseExact(uri.UserInfo, "D", out _));
            var id = Guid.Parse(uri.UserInfo); Need(id != Guid.Empty);
            Need(uri.Host is "hb.ru-msk.vkcloud-storage.ru" or "hb.vkcloud-storage.ru");
            var query = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var part in uri.Query.TrimStart('?').Split('&'))
            {
                var pair = part.Split('=', 2); Need(pair.Length == 2);
                var k = Uri.UnescapeDataString(pair[0]); var v = Uri.UnescapeDataString(pair[1]);
                Need(query.TryAdd(k, v));
            }
            Need(query.Keys.All(k => new[] { "type", "service", "encryption", "s3", "security", "flow" }.Contains(k)));
            Need(query["type"] == "xdrive" && query["service"] == "s3");
            Need(!query.TryGetValue("security", out var security) || security is "" or "none");
            Need(!query.TryGetValue("flow", out var flow) || flow == "");
            var enc = query["encryption"];
            const string head = "mlkem768x25519plus.native.1rtt.";
            Need(enc.StartsWith(head, StringComparison.Ordinal) && enc.Length > head.Length && enc.Length <= 4096 &&
                 !enc.Any(char.IsWhiteSpace) && !enc.Any(char.IsControl));
            var payload = query["s3"]; Need(payload.Length <= 12000 && Regex.IsMatch(payload, @"^[A-Za-z0-9_+/=-]+$"));
            payload = payload.Replace('-', '+').Replace('_', '/');
            payload = payload.PadRight((payload.Length + 3) / 4 * 4, '=');
            var bytes = Convert.FromBase64String(payload); Need(bytes.Length <= 8192);
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 4 });
            var data = document.RootElement; Need(data.ValueKind == JsonValueKind.Object);
            var fields = data.EnumerateObject().Select(p => p.Name).ToArray();
            Need(fields.Length == 7 && fields.Distinct(StringComparer.Ordinal).Count() == 7 && fields.All(k =>
                 new[] { "version", "endpoint", "region", "bucket", "prefix", "accessKey", "secretKey" }.Contains(k)));
            Need(data.GetProperty("version").GetInt32() == 1 && data.GetProperty("region").GetString() == "ru-msk");
            string Field(string k) => data.GetProperty(k).GetString() ?? throw new ProfileException();
            var endpoint = new Uri(Field("endpoint"));
            Need(endpoint.Scheme == "https" && endpoint.Port == 443 && endpoint.Host == uri.Host &&
                 endpoint.UserInfo == "" && endpoint.Query == "" && endpoint.Fragment == "" && endpoint.AbsolutePath == "/");
            var bucket = Field("bucket"); var prefix = Field("prefix");
            Need(Regex.IsMatch(bucket, @"^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$") && !bucket.StartsWith("xn--"));
            Need(prefix.Length <= 512 && Regex.IsMatch(prefix, @"^[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*/?$"));
            var access = Field("accessKey"); var secret = Field("secretKey");
            Need(new[] { access, secret }.All(s => s.Length is > 0 and <= 1024 && !string.IsNullOrWhiteSpace(s) && !s.Any(char.IsControl)));
            return new S3Profile(SafeName(Uri.UnescapeDataString(uri.Fragment.TrimStart('#'))), id, uri.Host,
                enc, endpoint.GetLeftPart(UriPartial.Authority), bucket, prefix.TrimEnd('/'), access, secret);
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            throw new ProfileException(); // Deliberately discard parser exceptions and their secret-bearing input.
        }
    }
    public string CreateConfig(int httpPort, int socksPort)
    {
        Need(httpPort is > 1023 and <= 65535 && socksPort is > 1023 and <= 65535 && httpPort != socksPort);
        var credentials = JsonSerializer.Serialize(new { endpoint = Endpoint, region = "ru-msk", bucket = Bucket, accessKey = AccessKey, secretKey = SecretKey });
        return JsonSerializer.Serialize(new
        {
            log = new { loglevel = "none" },
            inbounds = new object[] {
                new { tag = "http", listen = "127.0.0.1", port = httpPort, protocol = "http", settings = new { } },
                new { tag = "socks", listen = "127.0.0.1", port = socksPort, protocol = "socks", settings = new { auth = "noauth", udp = false } }
            },
            outbounds = new[] { new {
                tag = "s3", protocol = "vless",
                settings = new { vnext = new[] { new { address = Host, port = 443, users = new[] { new { id = Uuid.ToString(), encryption = Encryption } } } } },
                streamSettings = new { network = "xdrive", security = "none", address = BootstrapAddress, port = 443,
                    xdriveSettings = new { service = "S3", remoteFolder = Prefix, secrets = new[] { credentials },
                        segmentBytes = 262144, flushIntervalMs = 30, pollIntervalMs = 150, maxPollIntervalMs = 1200,
                        concurrency = 4, sessionTtlSeconds = 300 } },
                mux = new { enabled = true, concurrency = 8 }
            } }
        });
    }
}
