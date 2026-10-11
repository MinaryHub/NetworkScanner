using System;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace NetworkScanner.Secrets
{
    // 이전 버전 CredentialProtector가 setting.ini에 남긴 FTP 비밀번호 형식을 해석한다(1회 마이그레이션용).
    //   "KEYCHAIN"        : 값이 OS 자격 증명 저장소에 있음 → null 반환. 호출자는 OS 저장소에서
    //                       키 LegacyKey("ftp-password")로 읽는다(Mac/Linux 저장소의 account = key 규칙과 일치).
    //   "B64:" + base64   : Base64 난독화 → 디코드한 UTF-8.
    //   그 외             : Windows면 DPAPI(CurrentUser, 엔트로피 없음) 복호화 시도, 실패하거나 다른 OS면 평문으로 간주해 그대로 반환.
    public static class LegacyCredentialFormat
    {
        public const string KeychainMarker = "KEYCHAIN";
        public const string Base64Prefix = "B64:";

        // 이전 버전이 OS 저장소에 사용한 account 이름. 새 저장소에서 같은 키로 읽으면 그대로 보인다.
        public const string LegacyKey = "ftp-password";

        public static bool IsKeychainMarker(string? storedValue)
            => string.Equals(storedValue, KeychainMarker, StringComparison.Ordinal);

        // 저장된 값이 비어 있거나 "KEYCHAIN" 마커면 null. 절대 예외를 던지지 않는다.
        public static string? TryDecodeLegacy(string? storedValue)
        {
            if (string.IsNullOrEmpty(storedValue)) return null;
            if (IsKeychainMarker(storedValue)) return null;

            if (storedValue.StartsWith(Base64Prefix, StringComparison.Ordinal))
            {
                try
                {
                    return Encoding.UTF8.GetString(Convert.FromBase64String(storedValue.Substring(Base64Prefix.Length)));
                }
                catch
                {
                    return storedValue;
                }
            }

            if (OperatingSystem.IsWindows())
            {
                string? dpapi = TryDpapiUnprotect(storedValue);
                if (dpapi != null) return dpapi;
            }

            // 더 오래된 버전은 평문으로 저장했다. Windows DPAPI 값을 다른 OS에서 풀 수는 없으므로 그대로 반환한다.
            return storedValue;
        }

        [SupportedOSPlatform("windows")]
        private static string? TryDpapiUnprotect(string storedValue)
        {
            try
            {
                byte[] cipher = Convert.FromBase64String(storedValue);
                byte[] plain = ProtectedData.Unprotect(cipher, null, DataProtectionScope.CurrentUser);
                return Encoding.UTF8.GetString(plain);
            }
            catch
            {
                return null;
            }
        }
    }
}
