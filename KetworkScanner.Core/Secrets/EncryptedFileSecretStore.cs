using System;
using System.IO;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace KetworkScanner.Secrets
{
    // 플랫폼 독립 저장소. 비밀마다 <root>/secrets/<key>.secret 파일 하나에
    // nonce(12) || tag(16) || ciphertext 형식으로 AES-256-GCM 암호화해 저장한다.
    // 마스터 키(32바이트)는 <root>/secrets/master.key에 두며, 첫 바이트가 형식 마커다:
    //   0x01 = 원시 키(Unix: 파일 모드 0600으로만 보호)
    //   0x02 = DPAPI(CurrentUser)로 감싼 키(Windows: 키 파일 자체가 평문이 아니다)
    // 키 이름을 AAD(associated data)로 사용하므로 다른 키 이름으로 파일을 바꿔치기할 수 없다.
    public sealed class EncryptedFileSecretStore : ISecretStore
    {
        private const int NonceSize = 12;
        private const int TagSize = 16;
        private const int MasterKeySize = 32;
        private const byte FormatRawKey = 0x01;
        private const byte FormatDpapiKey = 0x02;
        private const string MasterKeyFileName = "master.key";
        private const string SecretExtension = ".secret";

        // DPAPI로 마스터 키를 감쌀 때 쓰는 추가 엔트로피(다른 앱의 DPAPI 블롭과 구분).
        private static readonly byte[] DpapiEntropy = Encoding.UTF8.GetBytes("NetworkScanner.master.key"); // 이름 변경 전 값 그대로(기존 키 파일 호환)

        private readonly string _directory;
        private readonly object _lock = new();
        private byte[]? _masterKey;

        public EncryptedFileSecretStore() : this(UserDataPaths.Root) { }

        public EncryptedFileSecretStore(string rootDirectory)
        {
            if (string.IsNullOrWhiteSpace(rootDirectory)) throw new ArgumentException("루트 디렉터리가 비어 있습니다.", nameof(rootDirectory));
            _directory = Path.Combine(rootDirectory, "secrets");
        }

        public string Name => "encrypted-file";

        public string Directory => _directory;

        public bool IsAvailable() => true;

        public bool TrySet(string key, string secret)
        {
            SecretKey.Validate(key);
            if (secret == null) throw new ArgumentNullException(nameof(secret));

            try
            {
                lock (_lock)
                {
                    byte[]? masterKey = LoadOrCreateMasterKey();
                    if (masterKey == null) return false;

                    byte[] plain = Encoding.UTF8.GetBytes(secret);
                    byte[] nonce = RandomNumberGenerator.GetBytes(NonceSize);
                    byte[] tag = new byte[TagSize];
                    byte[] cipher = new byte[plain.Length];

                    using (var aes = new AesGcm(masterKey, TagSize))
                    {
                        aes.Encrypt(nonce, plain, cipher, tag, Encoding.UTF8.GetBytes(key));
                    }

                    byte[] blob = new byte[NonceSize + TagSize + cipher.Length];
                    Buffer.BlockCopy(nonce, 0, blob, 0, NonceSize);
                    Buffer.BlockCopy(tag, 0, blob, NonceSize, TagSize);
                    Buffer.BlockCopy(cipher, 0, blob, NonceSize + TagSize, cipher.Length);

                    WritePrivateFile(SecretPath(key), blob);
                    CryptographicOperations.ZeroMemory(plain);
                    return true;
                }
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

            try
            {
                string path = SecretPath(key);
                if (!File.Exists(path)) return null;

                lock (_lock)
                {
                    byte[]? masterKey = LoadOrCreateMasterKey();
                    if (masterKey == null) return null;

                    byte[] blob = File.ReadAllBytes(path);
                    if (blob.Length < NonceSize + TagSize)
                    {
                        SecretStoreDiagnostics.Report(Name, "'" + key + "' 파일이 손상되었습니다(길이 부족).");
                        return null;
                    }

                    var nonce = new ReadOnlySpan<byte>(blob, 0, NonceSize);
                    var tag = new ReadOnlySpan<byte>(blob, NonceSize, TagSize);
                    var cipher = new ReadOnlySpan<byte>(blob, NonceSize + TagSize, blob.Length - NonceSize - TagSize);
                    byte[] plain = new byte[cipher.Length];

                    try
                    {
                        using var aes = new AesGcm(masterKey, TagSize);
                        aes.Decrypt(nonce, cipher, tag, plain, Encoding.UTF8.GetBytes(key));
                    }
                    catch (CryptographicException)
                    {
                        // 변조되었거나 다른 키 이름/마스터 키로 암호화된 파일.
                        SecretStoreDiagnostics.Report(Name, "'" + key + "' 파일을 복호화할 수 없습니다(변조 또는 키 불일치).");
                        return null;
                    }

                    string result = Encoding.UTF8.GetString(plain);
                    CryptographicOperations.ZeroMemory(plain);
                    return result;
                }
            }
            catch (Exception ex)
            {
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

        private string SecretPath(string key) => Path.Combine(_directory, key + SecretExtension);

        // 마스터 키를 메모리에 캐시한다. 없으면 생성하고, 손상/복호화 불가면 null.
        private byte[]? LoadOrCreateMasterKey()
        {
            if (_masterKey != null) return _masterKey;

            EnsureDirectory();
            string path = Path.Combine(_directory, MasterKeyFileName);

            if (File.Exists(path))
            {
                byte[]? loaded = UnwrapMasterKey(File.ReadAllBytes(path));
                if (loaded == null) return null;
                _masterKey = loaded;
                return _masterKey;
            }

            byte[] raw = RandomNumberGenerator.GetBytes(MasterKeySize);
            WritePrivateFile(path, WrapMasterKey(raw));
            _masterKey = raw;
            return _masterKey;
        }

        private byte[] WrapMasterKey(byte[] raw)
        {
            if (OperatingSystem.IsWindows())
            {
                byte[] wrapped = DpapiProtect(raw);
                byte[] file = new byte[1 + wrapped.Length];
                file[0] = FormatDpapiKey;
                Buffer.BlockCopy(wrapped, 0, file, 1, wrapped.Length);
                return file;
            }

            byte[] plainFile = new byte[1 + raw.Length];
            plainFile[0] = FormatRawKey;
            Buffer.BlockCopy(raw, 0, plainFile, 1, raw.Length);
            return plainFile;
        }

        private byte[]? UnwrapMasterKey(byte[] file)
        {
            if (file.Length < 2)
            {
                SecretStoreDiagnostics.Report(Name, "master.key 파일이 손상되었습니다.");
                return null;
            }

            byte[] body = new byte[file.Length - 1];
            Buffer.BlockCopy(file, 1, body, 0, body.Length);

            switch (file[0])
            {
                case FormatRawKey:
                    if (body.Length != MasterKeySize)
                    {
                        SecretStoreDiagnostics.Report(Name, "master.key 길이가 올바르지 않습니다.");
                        return null;
                    }
                    return body;

                case FormatDpapiKey:
                    if (!OperatingSystem.IsWindows())
                    {
                        SecretStoreDiagnostics.Report(Name, "master.key가 Windows DPAPI로 보호되어 있어 이 OS에서 열 수 없습니다.");
                        return null;
                    }
                    try
                    {
                        byte[] raw = DpapiUnprotect(body);
                        if (raw.Length != MasterKeySize)
                        {
                            SecretStoreDiagnostics.Report(Name, "master.key 길이가 올바르지 않습니다.");
                            return null;
                        }
                        return raw;
                    }
                    catch (Exception ex)
                    {
                        SecretStoreDiagnostics.Report(Name, "master.key DPAPI 복호화 실패: " + ex.Message);
                        return null;
                    }

                default:
                    SecretStoreDiagnostics.Report(Name, "master.key 형식 마커를 알 수 없습니다: 0x" + file[0].ToString("X2"));
                    return null;
            }
        }

        [SupportedOSPlatform("windows")]
        private static byte[] DpapiProtect(byte[] raw)
            => ProtectedData.Protect(raw, DpapiEntropy, DataProtectionScope.CurrentUser);

        [SupportedOSPlatform("windows")]
        private static byte[] DpapiUnprotect(byte[] wrapped)
            => ProtectedData.Unprotect(wrapped, DpapiEntropy, DataProtectionScope.CurrentUser);

        private void EnsureDirectory()
        {
            if (System.IO.Directory.Exists(_directory))
            {
                if (!OperatingSystem.IsWindows()) TrySetMode(_directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
                return;
            }

            if (OperatingSystem.IsWindows())
            {
                System.IO.Directory.CreateDirectory(_directory);
            }
            else
            {
                System.IO.Directory.CreateDirectory(_directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }
        }

        // 파일을 생성 시점부터 0600으로 만든다(umask에 의존하지 않도록 UnixCreateMode 사용).
        // 이미 존재하는 파일은 생성 모드가 적용되지 않으므로 기록 후 모드를 다시 설정한다.
        private static void WritePrivateFile(string path, byte[] content)
        {
            var options = new FileStreamOptions
            {
                Mode = FileMode.Create,
                Access = FileAccess.Write,
                Share = FileShare.None,
            };
            if (!OperatingSystem.IsWindows())
            {
                options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            }

            using (var stream = new FileStream(path, options))
            {
                stream.Write(content, 0, content.Length);
            }

            if (!OperatingSystem.IsWindows()) TrySetMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }

        [UnsupportedOSPlatform("windows")]
        private static void TrySetMode(string path, UnixFileMode mode)
        {
            try
            {
                if (File.GetUnixFileMode(path) != mode) File.SetUnixFileMode(path, mode);
            }
            catch
            {
                // 파일 시스템이 모드를 지원하지 않는 경우(FAT 등) — 저장 자체는 계속한다.
            }
        }
    }
}
