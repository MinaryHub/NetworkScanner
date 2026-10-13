using System;
using System.Threading;
using System.Threading.Tasks;

namespace KetworkScanner.Upload
{
    // 스캔 결과 파일 한 개를 원격 서버로 보내는 전송 구현(FTPS/SFTP/HTTPS). 실패는 예외로 알린다.
    public interface IResultUploader
    {
        UploadProtocol Protocol { get; }
        Task UploadAsync(string localPath, string remoteFileName, UploadSettings settings, CancellationToken ct);
    }

    public sealed class UploadException : Exception
    {
        public bool IsPermanent { get; }   // 인증 실패/지문 불일치 등 재시도해도 소용없는 오류
        public UploadException(string message, bool permanent = false, Exception? inner = null) : base(message, inner)
        {
            IsPermanent = permanent;
        }
    }

    public static class UploaderFactory
    {
        public static IResultUploader Create(UploadProtocol protocol) => protocol switch
        {
            UploadProtocol.Sftp => new SftpUploader(),
            UploadProtocol.Https => new HttpsUploader(),
            _ => new FtpUploader(),
        };
    }
}
