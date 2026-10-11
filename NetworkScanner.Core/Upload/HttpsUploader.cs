using System;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Threading;
using System.Threading.Tasks;

namespace NetworkScanner.Upload
{
    // HTTPS multipart POST 업로드. 중앙 수집 서버(API)로 보내는 경로이며, Bearer 토큰으로 인증한다.
    // Host에는 "collector.example.com" 또는 전체 URL("https://collector.example.com/api/scan")을 적을 수 있다.
    public sealed class HttpsUploader : IResultUploader
    {
        public UploadProtocol Protocol => UploadProtocol.Https;

        public async Task UploadAsync(string localPath, string remoteFileName, UploadSettings settings, CancellationToken ct)
        {
            Uri uri = BuildUri(settings);

            using var handler = new HttpClientHandler();
            if (!string.IsNullOrWhiteSpace(settings.ServerFingerprint))
            {
                string expected = settings.ServerFingerprint;
                handler.ServerCertificateCustomValidationCallback = (_, cert, _, errors) =>
                    cert != null && Fingerprint.Matches(expected, Fingerprint.Sha256Hex(cert.GetRawCertData()));
            }

            using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(60) };
            http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", settings.BearerToken);

            try
            {
                using var form = new MultipartFormDataContent();
                form.Add(new StringContent(remoteFileName), "name");
                await using FileStream fs = File.OpenRead(localPath);
                var file = new StreamContent(fs);
                file.Headers.ContentType = new MediaTypeHeaderValue(remoteFileName.EndsWith(".json", StringComparison.OrdinalIgnoreCase)
                    ? "application/json" : remoteFileName.EndsWith(".html", StringComparison.OrdinalIgnoreCase) ? "text/html" : "text/csv");
                form.Add(file, "file", remoteFileName);

                using HttpResponseMessage resp = await http.PostAsync(uri, form, ct).ConfigureAwait(false);
                if (!resp.IsSuccessStatusCode)
                {
                    int code = (int)resp.StatusCode;
                    bool permanent = code is 400 or 401 or 403 or 404 or 413 or 415 or 422;
                    throw new UploadException($"HTTP {code} {resp.ReasonPhrase}", permanent);
                }
            }
            catch (UploadException) { throw; }
            catch (Exception ex) when (ex is HttpRequestException || ex is IOException || ex is TaskCanceledException)
            {
                throw new UploadException(ex.Message, permanent: ex.InnerException is System.Security.Authentication.AuthenticationException, inner: ex);
            }
        }

        private static Uri BuildUri(UploadSettings s)
        {
            string host = s.Host.Trim();
            if (host.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || host.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                if (host.StartsWith("http://", StringComparison.OrdinalIgnoreCase) && !s.AllowInsecure)
                    throw new UploadException("Plain HTTP upload is not allowed.", permanent: true);
                return new Uri(host);
            }
            string path = string.IsNullOrWhiteSpace(s.RemoteDirectory) ? "/" : "/" + s.RemoteDirectory.Trim('/');
            return new UriBuilder("https", host, s.EffectivePort, path).Uri;
        }
    }
}
