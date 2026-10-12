using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace NetworkScanner.Discovery.Fingerprint
{
    // 한 번의 GET에서 관찰한 것들. FactsFrom()이 순수 함수로 Fact를 만든다(테스트용).
    internal sealed record HttpObservation(
        int Port,
        bool Https,
        string? Server,
        string? Title,
        string? Realm,
        string? PoweredBy,
        string? Generator,
        string? Location,
        string? CertSubjectCn,
        IReadOnlyList<string> CertDnsNames,
        string? CertIssuer,
        string? BodySnippet);

    // HTTP(S) 핑거프린트: 열린 웹 포트(최대 2개, 443→80 우선)에 GET / 를 보내 Server 헤더·<title>·인증 realm·
    // meta generator·인증서 이름을 모으고, HttpFingerprints 표로 제조사/장비 종류/OS를 추정한다.
    public sealed class HttpProbe : IFactProbe
    {
        public const string Source = "HTTP";
        public const int MaxPortsPerHost = 2;
        private const int MaxBodyBytes = 64 * 1024;
        private const int MaxRedirects = 2;

        public static readonly int[] HttpPorts = { 80, 8080, 8000, 8008, 8081, 8888 };
        public static readonly int[] HttpsPorts = { 443, 8443 };
        private static readonly int[] Preference = { 443, 80, 8443, 8080, 8000, 8008, 8081, 8888 };

        private static readonly Regex TitleRegex = new(@"<title[^>]*>(.*?)</title>", RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(200));
        private static readonly Regex GeneratorRegex = new(@"<meta[^>]+name\s*=\s*[""']generator[""'][^>]*content\s*=\s*[""']([^""']+)[""']|<meta[^>]+content\s*=\s*[""']([^""']+)[""'][^>]*name\s*=\s*[""']generator[""']", RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(200));
        private static readonly Regex MetaCharsetRegex = new(@"charset\s*=\s*[""']?\s*([A-Za-z0-9_\-]+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(200));
        private static readonly Regex RealmRegex = new(@"realm\s*=\s*(?:""([^""]*)""|([^,\s]+))", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(200));
        private static readonly Regex WhitespaceRegex = new(@"\s+", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(200));

        private readonly IReadOnlyList<(int Port, bool Https)>? _ports;

        static HttpProbe()
        {
            // EUC-KR 등 코드 페이지 인코딩(국산 공유기 페이지)을 읽기 위해 등록한다.
            try { Encoding.RegisterProvider(CodePagesEncodingProvider.Instance); } catch { }
        }

        public HttpProbe() { }

        // 테스트용: 포트/스킴을 직접 지정한다.
        internal HttpProbe(IReadOnlyList<(int Port, bool Https)> ports) => _ports = ports;

        public string Name => Source;

        public async Task<IReadOnlyList<Fact>> ProbeAsync(string ip, IReadOnlyList<int> openPorts, int timeoutMs, CancellationToken ct)
        {
            if (openPorts == null || openPorts.Count == 0) return ProbeTcp.Empty;
            List<(int Port, bool Https)> targets = SelectPorts(openPorts);
            if (targets.Count == 0) return ProbeTcp.Empty;

            var facts = new FactList(Source);
            try
            {
                foreach (var (port, https) in targets)
                {
                    if (ct.IsCancellationRequested) break;
                    HttpObservation? obs = await FetchAsync(ip, port, https, timeoutMs, ct).ConfigureAwait(false);
                    if (obs != null) FactsFrom(obs, facts);
                }
            }
            catch { }
            return facts.ToList();
        }

        internal List<(int Port, bool Https)> SelectPorts(IReadOnlyList<int> openPorts)
        {
            var result = new List<(int, bool)>();
            if (_ports != null)
            {
                foreach (var p in _ports) if (openPorts.Contains(p.Port)) result.Add(p);
                return result;
            }
            foreach (int p in Preference)
            {
                if (!openPorts.Contains(p)) continue;
                result.Add((p, HttpsPorts.Contains(p)));
                if (result.Count >= MaxPortsPerHost) break;
            }
            return result;
        }

        // ---------- 가져오기 ----------

        private sealed class CertInfo
        {
            public string? SubjectCn;
            public List<string> DnsNames = new();
            public string? Issuer;
        }

        internal static async Task<HttpObservation?> FetchAsync(string ip, int port, bool https, int timeoutMs, CancellationToken ct)
        {
            if (!IPAddress.TryParse(ip, out IPAddress? addr)) return null;
            var cert = new CertInfo();
            string? server = null, realm = null, poweredBy = null, location = null, title = null, generator = null, snippet = null;
            bool any = false;

            try
            {
                using CancellationTokenSource cts = ProbeTcp.Linked(ct, timeoutMs);
                using var handler = new SocketsHttpHandler
                {
                    AllowAutoRedirect = false,
                    UseCookies = false,
                    UseProxy = false,
                    ConnectTimeout = TimeSpan.FromMilliseconds(Math.Max(100, timeoutMs)),
                    SslOptions = new SslClientAuthenticationOptions
                    {
                        // 자체 서명 등 어떤 인증서든 받아들이고, 이름만 적어 둔다(TLS 평가는 다른 곳에서 한다).
                        RemoteCertificateValidationCallback = (_, certificate, _, _) => { Capture(certificate, cert); return true; },
                    },
                };
                using var client = new HttpClient(handler)
                {
                    Timeout = Timeout.InfiniteTimeSpan,
                    DefaultRequestVersion = HttpVersion.Version11,
                    DefaultVersionPolicy = HttpVersionPolicy.RequestVersionOrLower,
                };
                client.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", "Mozilla/5.0 NetworkScanner");
                client.DefaultRequestHeaders.TryAddWithoutValidation("Accept", "text/html,*/*;q=0.8");

                string host = addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? $"[{ip}]" : ip;
                var uri = new Uri($"{(https ? "https" : "http")}://{host}:{port}/");

                for (int hop = 0; hop <= MaxRedirects; hop++)
                {
                    using var request = new HttpRequestMessage(HttpMethod.Get, uri);
                    using HttpResponseMessage response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cts.Token).ConfigureAwait(false);
                    any = true;
                    server ??= HeaderValue(response, "Server");
                    poweredBy ??= HeaderValue(response, "X-Powered-By");
                    realm ??= ParseRealm(HeaderValue(response, "WWW-Authenticate"));

                    int status = (int)response.StatusCode;
                    if (status >= 300 && status < 400 && response.Headers.Location != null)
                    {
                        Uri next = response.Headers.Location.IsAbsoluteUri ? response.Headers.Location : new Uri(uri, response.Headers.Location);
                        location ??= next.ToString();
                        // 같은 호스트(IP)로의 리다이렉트만 따라간다(http→https 등). 다른 이름으로 가면 거기서 멈춘다.
                        bool sameHost = next.Host.Trim('[', ']').Equals(ip, StringComparison.OrdinalIgnoreCase);
                        if (!sameHost || hop == MaxRedirects) break;
                        uri = next;
                        continue;
                    }

                    string? contentType = response.Content.Headers.ContentType?.MediaType;
                    if (contentType == null || contentType.StartsWith("text/", StringComparison.OrdinalIgnoreCase)
                        || contentType.Contains("html", StringComparison.OrdinalIgnoreCase) || contentType.Contains("xml", StringComparison.OrdinalIgnoreCase))
                    {
                        byte[] body = await ReadLimitedAsync(response, cts.Token).ConfigureAwait(false);
                        string html = DecodeBody(body, response.Content.Headers.ContentType?.CharSet);
                        title = ExtractTitle(html);
                        generator = ExtractGenerator(html);
                        snippet = html.Length > 4096 ? html.Substring(0, 4096) : html;
                    }
                    break;
                }
            }
            catch
            {
                // 타임아웃/연결 거부/TLS 실패: 그때까지 모은 것만 쓴다.
            }

            if (!any && cert.SubjectCn == null && cert.DnsNames.Count == 0) return null;
            return new HttpObservation(port, https, server, title, realm, poweredBy, generator, location,
                cert.SubjectCn, cert.DnsNames, cert.Issuer, snippet);
        }

        private static void Capture(X509Certificate? certificate, CertInfo into)
        {
            if (certificate == null) return;
            try
            {
                X509Certificate2 c = certificate as X509Certificate2 ?? X509CertificateLoader.LoadCertificate(certificate.GetRawCertData());
                string cn = c.GetNameInfo(X509NameType.SimpleName, false);
                into.SubjectCn = string.IsNullOrWhiteSpace(cn) ? null : cn;
                into.Issuer = c.Issuer;
                foreach (X509Extension ext in c.Extensions)
                {
                    if (ext is X509SubjectAlternativeNameExtension san)
                        foreach (string dns in san.EnumerateDnsNames()) into.DnsNames.Add(dns);
                }
            }
            catch { }
        }

        private static string? HeaderValue(HttpResponseMessage response, string name)
        {
            if (response.Headers.TryGetValues(name, out IEnumerable<string>? values))
            {
                string v = string.Join(", ", values).Trim();
                if (v.Length > 0) return v;
            }
            if (response.Content.Headers.TryGetValues(name, out values))
            {
                string v = string.Join(", ", values).Trim();
                if (v.Length > 0) return v;
            }
            return null;
        }

        private static async Task<byte[]> ReadLimitedAsync(HttpResponseMessage response, CancellationToken ct)
        {
            using Stream stream = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
            var buffer = new byte[MaxBodyBytes];
            int total = 0;
            try
            {
                while (total < buffer.Length)
                {
                    int n = await stream.ReadAsync(buffer.AsMemory(total, buffer.Length - total), ct).ConfigureAwait(false);
                    if (n <= 0) break;
                    total += n;
                }
            }
            catch { }
            return total == buffer.Length ? buffer : buffer.AsSpan(0, total).ToArray();
        }

        // Content-Type charset → <meta charset> → UTF-8 순으로 디코딩한다.
        internal static string DecodeBody(byte[] body, string? charset)
        {
            Encoding? enc = TryEncoding(charset);
            if (enc == null)
            {
                string ascii = Encoding.Latin1.GetString(body, 0, Math.Min(body.Length, 4096));
                Match m = MetaCharsetRegex.Match(ascii);
                if (m.Success) enc = TryEncoding(m.Groups[1].Value);
            }
            return (enc ?? Encoding.UTF8).GetString(body);
        }

        private static Encoding? TryEncoding(string? name)
        {
            if (string.IsNullOrWhiteSpace(name)) return null;
            try { return Encoding.GetEncoding(name.Trim().Trim('"', '\'')); } catch { return null; }
        }

        internal static string? ExtractTitle(string html)
        {
            try
            {
                Match m = TitleRegex.Match(html);
                if (!m.Success) return null;
                string t = WhitespaceRegex.Replace(WebUtility.HtmlDecode(m.Groups[1].Value), " ").Trim();
                if (t.Length == 0) return null;
                return t.Length > 80 ? t.Substring(0, 80).TrimEnd() : t;
            }
            catch { return null; }
        }

        internal static string? ExtractGenerator(string html)
        {
            try
            {
                Match m = GeneratorRegex.Match(html);
                if (!m.Success) return null;
                string g = m.Groups[1].Success ? m.Groups[1].Value : m.Groups[2].Value;
                g = WebUtility.HtmlDecode(g).Trim();
                return g.Length == 0 ? null : (g.Length > 80 ? g.Substring(0, 80) : g);
            }
            catch { return null; }
        }

        internal static string? ParseRealm(string? wwwAuthenticate)
        {
            if (string.IsNullOrEmpty(wwwAuthenticate)) return null;
            try
            {
                Match m = RealmRegex.Match(wwwAuthenticate);
                if (!m.Success) return null;
                string r = (m.Groups[1].Success ? m.Groups[1].Value : m.Groups[2].Value).Trim();
                return r.Length == 0 ? null : (r.Length > 80 ? r.Substring(0, 80) : r);
            }
            catch { return null; }
        }

        // ---------- 관찰 → Fact ----------

        internal static IReadOnlyList<Fact> FactsFrom(HttpObservation obs)
        {
            var facts = new FactList(Source);
            FactsFrom(obs, facts);
            return facts.ToList();
        }

        internal static void FactsFrom(HttpObservation obs, FactList facts)
        {
            if (obs.Server != null) facts.Add(FactFields.Service, Clip(obs.Server, 80), Confidence.High);
            if (obs.Title != null) facts.Add(FactFields.Description, obs.Title, Confidence.Medium);
            if (obs.Realm != null) facts.Add(FactFields.Description, obs.Realm, Confidence.Medium);
            if (obs.PoweredBy != null) facts.Add(FactFields.Description, "X-Powered-By: " + Clip(obs.PoweredBy, 60), Confidence.Low);
            if (obs.Generator != null) facts.Add(FactFields.Description, "generator: " + obs.Generator, Confidence.Low);

            // 인증서 이름: IP·와일드카드·localhost가 아니면 호스트 이름 후보(Low).
            var names = new List<string>();
            if (obs.CertSubjectCn != null) names.Add(obs.CertSubjectCn);
            names.AddRange(obs.CertDnsNames);
            int added = 0;
            foreach (string n in names)
            {
                if (added >= 2) break;
                string name = n.Trim();
                if (name.Length == 0 || name.StartsWith('*') || IPAddress.TryParse(name, out _)) continue;
                if (name.Equals("localhost", StringComparison.OrdinalIgnoreCase)) continue;
                facts.Add(FactFields.Name, name, Confidence.Low);
                added++;
            }

            // 본문 조각 + realm + 리다이렉트 대상 + generator + 인증서 발급자/주체를 한 덩어리로 표와 대조한다.
            var body = new StringBuilder();
            if (obs.BodySnippet != null) body.Append(obs.BodySnippet).Append('\n');
            if (obs.Realm != null) body.Append(obs.Realm).Append('\n');
            if (obs.Location != null) body.Append(obs.Location).Append('\n');
            if (obs.Generator != null) body.Append(obs.Generator).Append('\n');
            if (obs.PoweredBy != null) body.Append(obs.PoweredBy).Append('\n');
            if (obs.CertIssuer != null) body.Append(obs.CertIssuer).Append('\n');
            if (obs.CertSubjectCn != null) body.Append(obs.CertSubjectCn).Append('\n');

            foreach (Fact f in HttpFingerprints.Match(obs.Server, obs.Title, body.ToString()))
                facts.Add(f.Field, f.Value, f.Confidence);
        }

        private static string Clip(string s, int max) => s.Length > max ? s.Substring(0, max) : s;
    }
}
