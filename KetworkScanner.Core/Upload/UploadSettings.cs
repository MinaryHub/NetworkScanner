using System;
using System.Text.Json.Serialization;

namespace KetworkScanner.Upload
{
    public enum UploadProtocol
    {
        Ftp,        // 평문 FTP(레거시 서버 호환용, 권장하지 않음)
        Ftps,       // FTP + Explicit TLS(기본값)
        FtpsImplicit,
        Sftp,       // SSH 파일 전송
        Https,      // HTTPS POST(multipart) + Bearer 토큰
    }

    // 스캔 결과 업로드 설정. UI/CLI/서비스가 같은 모델을 쓰고, IResultUploader 구현이 이 값으로 동작한다.
    public sealed class UploadSettings
    {
        public bool Enabled { get; set; }
        public UploadProtocol Protocol { get; set; } = UploadProtocol.Ftps;
        public string Host { get; set; } = "";
        public int Port { get; set; }                    // 0이면 프로토콜 기본 포트
        public string User { get; set; } = "";
        [JsonIgnore] public string Password { get; set; } = "";       // 메모리상 평문. 저장은 ISecretStore가 담당한다.
        public string RemoteDirectory { get; set; } = "/FTP";
        // 서버 인증서/호스트키 지문(SHA-256, 콜론 구분 hex). 비어 있으면 OS 신뢰 저장소(FTPS/HTTPS) 또는
        // 최초 접속 시 저장(SFTP, TOFU)으로 동작한다. 지정하면 반드시 일치해야 한다.
        public string ServerFingerprint { get; set; } = "";
        [JsonIgnore] public string BearerToken { get; set; } = "";    // HTTPS 전용
        public bool AllowInsecure { get; set; }          // 평문 FTP를 명시적으로 허용할 때만 true

        [JsonIgnore] public int EffectivePort => Port > 0 ? Port : Protocol switch
        {
            UploadProtocol.Sftp => 22,
            UploadProtocol.FtpsImplicit => 990,
            UploadProtocol.Https => 443,
            _ => 21,
        };

        public static UploadProtocol ParseProtocol(string? value) =>
            Enum.TryParse(value, ignoreCase: true, out UploadProtocol p) ? p : UploadProtocol.Ftps;

        public UploadSettings Clone() => (UploadSettings)MemberwiseClone();
    }
}
