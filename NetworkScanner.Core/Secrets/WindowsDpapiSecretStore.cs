using System;
using System.IO;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace NetworkScanner.Secrets
{
    // Windows 전용. 비밀을 DPAPI(CurrentUser, 엔트로피 = 키 이름)로 보호해
    // <root>/secrets/<key>.dpapi 파일에 저장한다. 같은 Windows 계정에서만 복호화할 수 있다.
    [SupportedOSPlatform("windows")]
    public sealed class WindowsDpapiSecretStore : ISecretStore
    {
        private const string Extension = ".dpapi";

        private readonly string _directory;
        private readonly object _lock = new();

        public WindowsDpapiSecretStore(string? rootDirectory = null)
        {
            _directory = Path.Combine(rootDirectory ?? UserDataPaths.Root, "secrets");
        }

        public string Name => "dpapi";

        public bool IsAvailable() => OperatingSystem.IsWindows();

        public bool TrySet(string key, string secret)
        {
            SecretKey.Validate(key);
            if (secret == null) throw new ArgumentNullException(nameof(secret));
            if (!OperatingSystem.IsWindows()) return false;

            try
            {
                byte[] plain = Encoding.UTF8.GetBytes(secret);
                byte[] cipher = ProtectedData.Protect(plain, Encoding.UTF8.GetBytes(key), DataProtectionScope.CurrentUser);
                CryptographicOperations.ZeroMemory(plain);

                lock (_lock)
                {
                    Directory.CreateDirectory(_directory);
                    File.WriteAllBytes(SecretPath(key), cipher);
                }
                return true;
            }
            catch (Exception ex)
            {
                SecretStoreDiagnostics.Report(Name, "'" + key + "' 저장 실패: " + ex.Message);
                return false;
            }
        }

        public string? Get(string key)
        {
            SecretKey.Validate(key);
            if (!OperatingSystem.IsWindows()) return null;

            try
            {
                string path = SecretPath(key);
                if (!File.Exists(path)) return null;

                byte[] cipher;
                lock (_lock) cipher = File.ReadAllBytes(path);

                byte[] plain = ProtectedData.Unprotect(cipher, Encoding.UTF8.GetBytes(key), DataProtectionScope.CurrentUser);
                string result = Encoding.UTF8.GetString(plain);
                CryptographicOperations.ZeroMemory(plain);
                return result;
            }
            catch (Exception ex)
            {
                // 다른 계정/머신에서 만든 파일이거나 손상된 경우.
                SecretStoreDiagnostics.Report(Name, "'" + key + "' 읽기 실패: " + ex.Message);
                return null;
            }
        }

        public void Remove(string key)
        {
            SecretKey.Validate(key);

            try
            {
                lock (_lock)
                {
                    string path = SecretPath(key);
                    if (File.Exists(path)) File.Delete(path);
                }
            }
            catch (Exception ex)
            {
                SecretStoreDiagnostics.Report(Name, "'" + key + "' 삭제 실패: " + ex.Message);
            }
        }

        private string SecretPath(string key) => Path.Combine(_directory, key + Extension);
    }
}
