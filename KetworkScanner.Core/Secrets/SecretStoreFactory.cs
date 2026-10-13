using System;
using System.Collections.Generic;
using System.Linq;

namespace KetworkScanner.Secrets
{
    // 현재 OS에 맞는 기본 저장소 체인을 만든다:
    //   [OS 자격 증명 저장소(사용 가능할 때만), EncryptedFileSecretStore]
    // Base64 난독화 같은 평문 폴백은 없다 — 마지막 단계도 항상 암호화 파일 저장소다.
    public static class SecretStoreFactory
    {
        public static ISecretStore CreateDefault(string? rootDirectory = null)
        {
            string root = rootDirectory ?? UserDataPaths.Root;
            var stores = new List<ISecretStore>();

            ISecretStore? osStore = CreateOsStore(root);
            if (osStore != null && osStore.IsAvailable()) stores.Add(osStore);

            stores.Add(new EncryptedFileSecretStore(root));
            return new FallbackSecretStore(stores);
        }

        private static ISecretStore? CreateOsStore(string root)
        {
            if (OperatingSystem.IsWindows()) return new WindowsDpapiSecretStore(root);
            if (OperatingSystem.IsMacOS()) return new MacKeychainSecretStore();
            if (OperatingSystem.IsLinux()) return new LinuxSecretToolSecretStore();
            return null;
        }
    }

    // 우선순위 목록으로 묶인 저장소.
    // - TrySet: 처음 성공한 저장소에 쓰고, 나머지에서는 같은 키를 지운다(오래된 복사본이 새 값을 가리지 않도록).
    // - Get: 처음 null이 아닌 값을 반환.
    // - Remove: 모든 저장소에서 삭제.
    public sealed class FallbackSecretStore : ISecretStore
    {
        private readonly IReadOnlyList<ISecretStore> _stores;
        private volatile ISecretStore? _lastUsed;

        public FallbackSecretStore(IEnumerable<ISecretStore> stores)
        {
            if (stores == null) throw new ArgumentNullException(nameof(stores));
            _stores = stores.ToList();
            if (_stores.Count == 0) throw new ArgumentException("저장소가 하나 이상 필요합니다.", nameof(stores));
        }

        public IReadOnlyList<ISecretStore> Stores => _stores;

        // 마지막으로 실제 읽기/쓰기에 성공한 저장소(진단용).
        public ISecretStore? LastUsed => _lastUsed;

        public string Name => "fallback(" + string.Join(">", _stores.Select(s => s.Name)) + ")";

        public bool IsAvailable() => _stores.Any(s => s.IsAvailable());

        public bool TrySet(string key, string secret)
        {
            SecretKey.Validate(key);
            if (secret == null) throw new ArgumentNullException(nameof(secret));

            for (int i = 0; i < _stores.Count; i++)
            {
                if (!_stores[i].TrySet(key, secret)) continue;

                _lastUsed = _stores[i];
                for (int j = 0; j < _stores.Count; j++)
                {
                    if (j != i) _stores[j].Remove(key);
                }
                return true;
            }

            SecretStoreDiagnostics.Report(Name, "'" + key + "'를 저장할 수 있는 저장소가 없습니다.");
            return false;
        }

        public string? Get(string key)
        {
            SecretKey.Validate(key);

            foreach (ISecretStore store in _stores)
            {
                string? value = store.Get(key);
                if (value == null) continue;

                _lastUsed = store;
                return value;
            }
            return null;
        }

        public void Remove(string key)
        {
            SecretKey.Validate(key);

            foreach (ISecretStore store in _stores) store.Remove(key);
        }
    }
}
