using System.Text;
using NetworkScanner.Secrets;

namespace NetworkScanner.Tests
{
    public class EncryptedFileSecretStoreTests : IDisposable
    {
        private readonly string _root;
        private readonly EncryptedFileSecretStore _store;

        public EncryptedFileSecretStoreTests()
        {
            _root = Path.Combine(Path.GetTempPath(), "nstest-secrets-" + Guid.NewGuid().ToString("N"));
            _store = new EncryptedFileSecretStore(_root);
        }

        public void Dispose()
        {
            try { Directory.Delete(_root, recursive: true); } catch { }
        }

        [Fact]
        public void RoundTrip_SetThenGet_ReturnsOriginal()
        {
            string secret = "s3cr3t-P@ss \"quoted\" \\ 한글 \n newline";

            Assert.True(_store.TrySet("ftp-password", secret));
            Assert.Equal(secret, _store.Get("ftp-password"));

            // 파일에 평문이 남아 있어서는 안 된다.
            byte[] raw = File.ReadAllBytes(Path.Combine(_root, "secrets", "ftp-password.secret"));
            Assert.True(raw.AsSpan().IndexOf(Encoding.UTF8.GetBytes("s3cr3t-P@ss")) < 0);
            Assert.Equal(12 + 16 + Encoding.UTF8.GetByteCount(secret), raw.Length);
        }

        [Fact]
        public void Overwrite_ReplacesPreviousValue()
        {
            Assert.True(_store.TrySet("k", "first"));
            Assert.True(_store.TrySet("k", "second"));

            Assert.Equal("second", _store.Get("k"));
        }

        [Fact]
        public void Get_MissingKey_ReturnsNull()
        {
            Assert.Null(_store.Get("does-not-exist"));
        }

        [Fact]
        public void Remove_ThenGet_ReturnsNull()
        {
            Assert.True(_store.TrySet("k", "v"));
            _store.Remove("k");

            Assert.Null(_store.Get("k"));
            _store.Remove("k"); // 없는 키 삭제는 조용히 성공
        }

        [Fact]
        public void Get_TamperedCiphertext_ReturnsNullAndReportsError()
        {
            Assert.True(_store.TrySet("k", "value-to-tamper"));
            string path = Path.Combine(_root, "secrets", "k.secret");
            byte[] blob = File.ReadAllBytes(path);
            blob[^1] ^= 0x01; // 암호문 마지막 바이트 변조
            File.WriteAllBytes(path, blob);

            var errors = new List<string>();
            var previous = SecretStoreDiagnostics.OnError;
            SecretStoreDiagnostics.OnError = errors.Add;
            try
            {
                Assert.Null(_store.Get("k"));
            }
            finally
            {
                SecretStoreDiagnostics.OnError = previous;
            }
            Assert.Contains(errors, e => e.Contains("encrypted-file"));
        }

        [Fact]
        public void Get_SecretFileRenamedToAnotherKey_ReturnsNull()
        {
            // AAD = 키 이름이므로 파일을 다른 키 이름으로 바꾸면 복호화에 실패해야 한다.
            Assert.True(_store.TrySet("alpha", "value"));
            string dir = Path.Combine(_root, "secrets");
            File.Move(Path.Combine(dir, "alpha.secret"), Path.Combine(dir, "beta.secret"));

            Assert.Null(_store.Get("beta"));
            Assert.Null(_store.Get("alpha"));
        }

        [Fact]
        public void NewInstance_SameDirectory_ReadsExistingSecret()
        {
            Assert.True(_store.TrySet("k", "persisted"));

            var reopened = new EncryptedFileSecretStore(_root);
            Assert.Equal("persisted", reopened.Get("k"));
        }

        [Theory]
        [InlineData("")]
        [InlineData("../etc")]
        [InlineData("a b")]
        [InlineData("key/name")]
        [InlineData("한글")]
        public void InvalidKeyName_ThrowsArgumentException(string key)
        {
            Assert.Throws<ArgumentException>(() => _store.TrySet(key, "v"));
            Assert.Throws<ArgumentException>(() => _store.Get(key));
            Assert.Throws<ArgumentException>(() => _store.Remove(key));
        }

        [Fact]
        public void ValidKeyNames_AreAccepted()
        {
            Assert.True(SecretKey.IsValid("ftp-password"));
            Assert.True(SecretKey.IsValid("a.b_C-9"));
            Assert.False(SecretKey.IsValid(null));
        }

        [Fact]
        public void Unix_KeyAndSecretFilesAre0600_DirectoryIs0700()
        {
            if (OperatingSystem.IsWindows()) return; // Unix 파일 모드는 Windows에 없다

            Assert.True(_store.TrySet("k", "v"));
            string dir = Path.Combine(_root, "secrets");
            var rw = UnixFileMode.UserRead | UnixFileMode.UserWrite;

            Assert.Equal(rw, File.GetUnixFileMode(Path.Combine(dir, "master.key")));
            Assert.Equal(rw, File.GetUnixFileMode(Path.Combine(dir, "k.secret")));
            Assert.Equal(rw | UnixFileMode.UserExecute, File.GetUnixFileMode(dir));
        }

        [Fact]
        public void Unix_MasterKeyFile_HasRawFormatMarker()
        {
            if (OperatingSystem.IsWindows()) return; // Windows는 0x02(DPAPI) — 이 머신에서는 검증 불가

            Assert.True(_store.TrySet("k", "v"));
            byte[] key = File.ReadAllBytes(Path.Combine(_root, "secrets", "master.key"));

            Assert.Equal(1 + 32, key.Length);
            Assert.Equal(0x01, key[0]);
        }

        [Fact]
        public void Get_CorruptMasterKey_ReturnsNull()
        {
            Assert.True(_store.TrySet("k", "v"));
            string keyPath = Path.Combine(_root, "secrets", "master.key");
            File.WriteAllBytes(keyPath, new byte[] { 0x7F, 1, 2, 3 });

            var reopened = new EncryptedFileSecretStore(_root);
            Assert.Null(reopened.Get("k"));
            Assert.False(reopened.TrySet("k2", "v2"));
        }
    }

    public class FallbackSecretStoreTests
    {
        // 테스트용 인메모리 저장소. 실패를 흉내낼 수 있다.
        private sealed class FakeStore : ISecretStore
        {
            public readonly Dictionary<string, string> Data = new();
            public bool FailSet;
            public int RemoveCalls;

            public FakeStore(string name) { Name = name; }
            public string Name { get; }
            public bool IsAvailable() => true;
            public bool TrySet(string key, string secret)
            {
                if (FailSet) return false;
                Data[key] = secret;
                return true;
            }
            public string? Get(string key) => Data.TryGetValue(key, out var v) ? v : null;
            public void Remove(string key) { RemoveCalls++; Data.Remove(key); }
        }

        [Fact]
        public void TrySet_FirstStoreFails_WritesToSecondAndRecordsLastUsed()
        {
            var first = new FakeStore("first") { FailSet = true };
            var second = new FakeStore("second");
            var fallback = new FallbackSecretStore(new ISecretStore[] { first, second });

            Assert.True(fallback.TrySet("k", "v"));

            Assert.False(first.Data.ContainsKey("k"));
            Assert.Equal("v", second.Data["k"]);
            Assert.Same(second, fallback.LastUsed);
            Assert.Equal("v", fallback.Get("k"));
        }

        [Fact]
        public void TrySet_FirstStoreSucceeds_RemovesStaleCopyFromOthers()
        {
            var first = new FakeStore("first");
            var second = new FakeStore("second");
            second.Data["k"] = "stale";
            var fallback = new FallbackSecretStore(new ISecretStore[] { first, second });

            Assert.True(fallback.TrySet("k", "fresh"));

            Assert.Equal("fresh", first.Data["k"]);
            Assert.False(second.Data.ContainsKey("k"));
            Assert.Same(first, fallback.LastUsed);
        }

        [Fact]
        public void Get_FirstStoreEmpty_FallsThroughToSecond()
        {
            var first = new FakeStore("first");
            var second = new FakeStore("second");
            second.Data["k"] = "from-second";
            var fallback = new FallbackSecretStore(new ISecretStore[] { first, second });

            Assert.Equal("from-second", fallback.Get("k"));
            Assert.Same(second, fallback.LastUsed);
            Assert.Null(fallback.Get("missing"));
        }

        [Fact]
        public void Remove_RemovesFromAllStores()
        {
            var first = new FakeStore("first");
            var second = new FakeStore("second");
            first.Data["k"] = "a";
            second.Data["k"] = "b";
            var fallback = new FallbackSecretStore(new ISecretStore[] { first, second });

            fallback.Remove("k");

            Assert.Empty(first.Data);
            Assert.Empty(second.Data);
        }

        [Fact]
        public void TrySet_AllStoresFail_ReturnsFalse()
        {
            var first = new FakeStore("first") { FailSet = true };
            var second = new FakeStore("second") { FailSet = true };
            var fallback = new FallbackSecretStore(new ISecretStore[] { first, second });

            Assert.False(fallback.TrySet("k", "v"));
            Assert.Null(fallback.LastUsed);
        }

        [Fact]
        public void Name_ListsStoresInOrder()
        {
            var fallback = new FallbackSecretStore(new ISecretStore[] { new FakeStore("a"), new FakeStore("b") });

            Assert.Equal("fallback(a>b)", fallback.Name);
            Assert.Equal(2, fallback.Stores.Count);
        }

        [Fact]
        public void CreateDefault_EndsWithEncryptedFileStore_AndRoundTrips()
        {
            string root = Path.Combine(Path.GetTempPath(), "nstest-factory-" + Guid.NewGuid().ToString("N"));
            try
            {
                var store = Assert.IsType<FallbackSecretStore>(SecretStoreFactory.CreateDefault(root));

                Assert.IsType<EncryptedFileSecretStore>(store.Stores[^1]);
                Assert.DoesNotContain(store.Stores, s => s.Name.Contains("b64", StringComparison.OrdinalIgnoreCase));

                // OS 저장소가 사용 가능한 머신에서는 그쪽에 기록될 수 있으므로 반드시 정리한다.
                string key = "nstest-factory-" + Guid.NewGuid().ToString("N").Substring(0, 8);
                try
                {
                    Assert.True(store.TrySet(key, "round-trip"));
                    Assert.Equal("round-trip", store.Get(key));
                    Assert.NotNull(store.LastUsed);
                }
                finally
                {
                    store.Remove(key);
                }
                Assert.Null(store.Get(key));
            }
            finally
            {
                try { Directory.Delete(root, recursive: true); } catch { }
            }
        }
    }

    public class LegacyCredentialFormatTests
    {
        [Fact]
        public void TryDecodeLegacy_B64Prefixed_DecodesUtf8()
        {
            string encoded = "B64:" + Convert.ToBase64String(Encoding.UTF8.GetBytes("fallback-pw 한글"));

            Assert.Equal("fallback-pw 한글", LegacyCredentialFormat.TryDecodeLegacy(encoded));
        }

        [Fact]
        public void TryDecodeLegacy_B64WithInvalidPayload_ReturnsAsIs()
        {
            Assert.Equal("B64:!!!", LegacyCredentialFormat.TryDecodeLegacy("B64:!!!"));
        }

        [Fact]
        public void TryDecodeLegacy_KeychainMarker_ReturnsNull()
        {
            Assert.Null(LegacyCredentialFormat.TryDecodeLegacy("KEYCHAIN"));
            Assert.True(LegacyCredentialFormat.IsKeychainMarker("KEYCHAIN"));
            Assert.Equal("ftp-password", LegacyCredentialFormat.LegacyKey);
        }

        [Fact]
        public void TryDecodeLegacy_EmptyOrNull_ReturnsNull()
        {
            Assert.Null(LegacyCredentialFormat.TryDecodeLegacy(""));
            Assert.Null(LegacyCredentialFormat.TryDecodeLegacy(null));
        }

        [Fact]
        public void TryDecodeLegacy_Plaintext_ReturnsAsIs()
        {
            // Windows에서는 DPAPI 복호화를 시도하지만 Base64가 아니거나 복호화 실패 시 그대로 반환해야 한다.
            Assert.Equal("old-plaintext-password", LegacyCredentialFormat.TryDecodeLegacy("old-plaintext-password"));
            Assert.Equal("AAAA", LegacyCredentialFormat.TryDecodeLegacy("AAAA")); // 유효한 Base64지만 DPAPI 블롭은 아님
        }
    }

    public class MacKeychainSecretStoreTests
    {
        [Fact]
        public void Keychain_SetGetRemove_RoundTrip()
        {
            if (!OperatingSystem.IsMacOS()) return;
            var store = new MacKeychainSecretStore();
            if (!store.IsAvailable()) return;

            // 개발 머신의 실제 로그인 Keychain에 기록되므로, 실패하더라도 반드시 항목을 제거한다.
            string key = "test-" + Guid.NewGuid().ToString("N").Substring(0, 12);
            // 따옴표/백슬래시/탭/비ASCII는 security가 16진수로 출력하는 경로, 단순 문자열과 16진수처럼 보이는 문자열은 따옴표 출력 경로를 검증한다.
            string secret = "p@ss'w$#rd \"q\" \\x \\t `t`\tTAB 한글 ;end";
            try
            {
                Assert.Null(store.Get(key));
                Assert.True(store.TrySet(key, secret));
                Assert.Equal(secret, store.Get(key));

                // -U: 기존 항목 갱신
                Assert.True(store.TrySet(key, "updated"));
                Assert.Equal("updated", store.Get(key));

                Assert.True(store.TrySet(key, "deadbeef")); // 16진수처럼 보여도 평문으로 돌아와야 한다
                Assert.Equal("deadbeef", store.Get(key));

                Assert.True(store.TrySet(key, ""));
                Assert.Equal("", store.Get(key));
            }
            finally
            {
                store.Remove(key);
            }

            Assert.Null(store.Get(key));
            store.Remove(key); // 없는 항목 삭제는 오류 없이 지나간다
        }

        [Fact]
        public void Keychain_SecretWithNewline_IsRejected()
        {
            if (!OperatingSystem.IsMacOS()) return;
            var store = new MacKeychainSecretStore();
            if (!store.IsAvailable()) return;

            string key = "test-" + Guid.NewGuid().ToString("N").Substring(0, 12);
            try
            {
                Assert.False(store.TrySet(key, "line1\nline2"));
                Assert.Null(store.Get(key));
            }
            finally
            {
                store.Remove(key);
            }
        }

        [Fact]
        public void Keychain_InvalidKey_Throws()
        {
            if (!OperatingSystem.IsMacOS()) return;

            var store = new MacKeychainSecretStore();
            Assert.Throws<ArgumentException>(() =>
            {
                if (OperatingSystem.IsMacOS()) store.Get("bad key"); // 람다 안에서도 플랫폼 가드(CA1416)
            });
        }
    }
}
