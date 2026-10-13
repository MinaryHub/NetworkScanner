using System;
using System.Collections.Concurrent;
using System.IO;
using System.Reflection;
using PdfSharp.Fonts;

namespace KetworkScanner.Reports
{
    // PdfSharp용 폰트 리졸버. 어셈블리에 임베드된 나눔고딕(SIL OFL)만 제공하므로
    // OS에 설치된 폰트와 무관하게 Windows/macOS/Linux 어디서나 한글이 같은 모양으로 렌더링된다.
    public sealed class NanumFontResolver : IFontResolver
    {
        // XFont에 넘기는 패밀리 이름. 굵기는 XFontStyleEx로 지정한다.
        public const string FamilyName = "Nanum Gothic";

        private const string RegularFace = "NanumGothic#R";
        private const string BoldFace = "NanumGothic#B";

        private const string RegularResource = "KetworkScanner.Fonts.NanumGothic.ttf";
        private const string BoldResource = "KetworkScanner.Fonts.NanumGothicBold.ttf";

        public static NanumFontResolver Instance { get; } = new();

        private static readonly object RegisterLock = new();
        private static bool _registered;

        // 리소스 바이트는 2MB 정도라 한 번만 읽어 캐시한다.
        private readonly ConcurrentDictionary<string, byte[]> _cache = new(StringComparer.Ordinal);

        private NanumFontResolver() { }

        // GlobalFontSettings.FontResolver는 프로세스 전역이므로 한 번만, 스레드 안전하게 등록한다.
        public static void EnsureRegistered()
        {
            if (_registered) return;
            lock (RegisterLock)
            {
                if (_registered) return;
                if (GlobalFontSettings.FontResolver is not NanumFontResolver)
                    GlobalFontSettings.FontResolver = Instance;
                _registered = true;
            }
        }

        public FontResolverInfo? ResolveTypeface(string familyName, bool bold, bool italic)
        {
            // 패밀리 이름은 대소문자/공백 차이를 무시하고 모두 나눔고딕으로 매핑한다(이 앱은 다른 폰트를 쓰지 않는다).
            // 이탤릭 폰트 파일은 없으므로 PdfSharp가 기울임을 흉내 내도록(simulate) 알린다.
            return new FontResolverInfo(bold ? BoldFace : RegularFace, mustSimulateBold: false, mustSimulateItalic: italic);
        }

        public byte[]? GetFont(string faceName)
        {
            string resource = faceName switch
            {
                BoldFace => BoldResource,
                RegularFace => RegularResource,
                _ => RegularResource,
            };
            return _cache.GetOrAdd(resource, LoadResource);
        }

        private static byte[] LoadResource(string name)
        {
            Assembly asm = typeof(NanumFontResolver).Assembly;
            using Stream? stream = asm.GetManifestResourceStream(name)
                ?? throw new InvalidOperationException($"Embedded font resource not found: {name}");
            using var ms = new MemoryStream();
            stream.CopyTo(ms);
            return ms.ToArray();
        }
    }
}
