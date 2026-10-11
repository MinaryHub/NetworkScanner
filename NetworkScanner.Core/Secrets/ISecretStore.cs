using System;
using System.Text.RegularExpressions;

namespace NetworkScanner.Secrets
{
    // 비밀 값(FTP 비밀번호 등)을 키 이름으로 저장/조회/삭제하는 저장소 추상화.
    // 구현체는 런타임 실패(도구 없음, 권한 거부, 파일 손상 등)에 대해 예외를 던지지 않고
    // SecretStoreDiagnostics.OnError로 보고한 뒤 false/null을 반환해야 한다.
    // 단, 잘못된 키 이름(SecretKey.Validate 참고)은 프로그래밍 오류이므로 ArgumentException을 던진다.
    public interface ISecretStore
    {
        // 로그/진단용 식별자 ("dpapi", "keychain", "libsecret", "encrypted-file")
        string Name { get; }

        // 이 OS/환경에서 사용 가능한지 (도구 존재, 데몬 접근 가능 등)
        bool IsAvailable();

        bool TrySet(string key, string secret);

        // 없으면 null
        string? Get(string key);

        void Remove(string key);
    }

    // 키 이름 규칙. 파일 이름/명령 인자로 그대로 쓰이므로 안전한 문자만 허용한다.
    public static class SecretKey
    {
        private static readonly Regex Pattern = new("^[A-Za-z0-9._-]+$", RegexOptions.Compiled);

        public static bool IsValid(string? key) => key != null && Pattern.IsMatch(key);

        public static void Validate(string key)
        {
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (!Pattern.IsMatch(key))
            {
                throw new ArgumentException("비밀 키 이름은 [A-Za-z0-9._-]+ 형식이어야 합니다: '" + key + "'", nameof(key));
            }
        }
    }
}
