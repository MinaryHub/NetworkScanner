using System;
using System.IO;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using FluentFTP;
using FluentFTP.Exceptions;

namespace NetworkScanner.Upload
{
    // FTP / FTPS(Explicit·Implicit TLS) 업로드. 기본은 Explicit TLS이며, 평문 FTP는 설정에서 명시적으로 허용했을 때만 쓴다.
    // 서버 인증서는 OS 신뢰 저장소로 검증하고, 지문이 설정돼 있으면 지문 일치를 추가로(또는 대신) 요구한다.
    public sealed class FtpUploader : IResultUploader
    {
        public UploadProtocol Protocol => UploadProtocol.Ftps;

        public async Task UploadAsync(string localPath, string remoteFileName, UploadSettings settings, CancellationToken ct)
        {
            if (settings.Protocol == UploadProtocol.Ftp && !settings.AllowInsecure)
                throw new UploadException(Localization.T("settings.invalid.insecureftp"), permanent: true);

            await using var client = new AsyncFtpClient(settings.Host, settings.User, settings.Password, settings.EffectivePort);
            client.Config.EncryptionMode = settings.Protocol switch
            {
                UploadProtocol.Ftp => FtpEncryptionMode.None,
                UploadProtocol.FtpsImplicit => FtpEncryptionMode.Implicit,
                _ => FtpEncryptionMode.Explicit,
            };
            client.Config.DataConnectionEncryption = client.Config.EncryptionMode != FtpEncryptionMode.None;
            client.Config.ValidateAnyCertificate = false;
            client.Config.ConnectTimeout = 15000;
            client.Config.ReadTimeout = 30000;
            client.Config.DataConnectionConnectTimeout = 15000;
            client.Config.DataConnectionReadTimeout = 30000;
            client.Config.RetryAttempts = 1;

            string expected = settings.ServerFingerprint;
            client.ValidateCertificate += (_, e) =>
            {
                if (!string.IsNullOrWhiteSpace(expected))
                {
                    e.Accept = Fingerprint.Matches(expected, Fingerprint.Sha256Hex(e.Certificate.GetRawCertData()));
                    return;
                }
                e.Accept = e.PolicyErrors == SslPolicyErrors.None;
            };

            try
            {
                await client.Connect(ct).ConfigureAwait(false);

                string remoteDir = string.IsNullOrWhiteSpace(settings.RemoteDirectory) ? "/" : settings.RemoteDirectory.TrimEnd('/');
                string remotePath = remoteDir + "/" + remoteFileName;
                FtpStatus status = await client.UploadFile(localPath, remotePath, FtpRemoteExists.Overwrite, createRemoteDir: true, token: ct)
                    .ConfigureAwait(false);
                if (status == FtpStatus.Failed)
                    throw new UploadException("FTP upload reported failure: " + remotePath);
            }
            catch (UploadException) { throw; }
            catch (FtpAuthenticationException ex)
            {
                throw new UploadException(ex.Message, permanent: true, inner: ex);
            }
            catch (Exception ex) when (ex is FtpException || ex is IOException || ex is System.Net.Sockets.SocketException
                                       || ex is TimeoutException || ex is System.Security.Authentication.AuthenticationException)
            {
                bool permanent = ex is System.Security.Authentication.AuthenticationException; // 인증서/지문 거부
                throw new UploadException(ex.Message, permanent, ex);
            }
        }
    }
}
