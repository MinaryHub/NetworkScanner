using System.Security.Cryptography;
using System.Text;

namespace KetworkScanner.Collector;

public sealed record Principal(string Site, bool IsAdmin)
{
    public bool CanView(string site) => IsAdmin || string.Equals(Site, site, StringComparison.OrdinalIgnoreCase);
}

// 토큰 → 사이트 매핑. 토큰을 SHA-256으로 해시해 길이를 맞춘 뒤 FixedTimeEquals로 비교한다(타이밍 공격 방지).
public sealed class TokenRegistry
{
    public const string CookieName = "collector_token";

    private readonly List<(byte[] Hash, Principal Who)> _entries = new();

    public TokenRegistry(CollectorOptions options)
    {
        var sites = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (TokenEntry t in options.Tokens)
        {
            string site = t.Site.Trim();
            _entries.Add((Hash(t.Token.Trim()), new Principal(site, IsAdmin: false)));
            sites.Add(site);
        }
        if (!string.IsNullOrWhiteSpace(options.AdminToken))
            _entries.Add((Hash(options.AdminToken.Trim()), new Principal("", IsAdmin: true)));
        Sites = sites.ToArray();
    }

    // 설정에 등록된 사이트 목록(업로드가 아직 없어도 대시보드에 보이도록).
    public IReadOnlyList<string> Sites { get; }

    public Principal? Match(string? token)
    {
        if (string.IsNullOrEmpty(token)) return null;
        byte[] h = Hash(token.Trim());
        Principal? found = null;
        // 일치해도 끝까지 돌아 비교 시간을 일정하게 유지한다.
        foreach ((byte[] hash, Principal who) in _entries)
        {
            if (CryptographicOperations.FixedTimeEquals(h, hash)) found ??= who;
        }
        return found;
    }

    // Authorization: Bearer → (허용 시) 쿠키 → (허용 시) ?token= 순서로 찾는다. Bearer 헤더가 있으면 그것만 본다.
    // 수집 서버의 엔드포인트는 모두 allowQuery=false 로 호출한다(URL의 토큰은 로그/히스토리에 남으므로 받지 않는다).
    public Principal? Resolve(HttpRequest request, bool allowCookie, bool allowQuery)
    {
        string? auth = request.Headers.Authorization.FirstOrDefault();
        if (!string.IsNullOrEmpty(auth))
        {
            return auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) ? Match(auth.Substring(7)) : null;
        }
        if (allowCookie && request.Cookies.TryGetValue(CookieName, out string? cookie))
        {
            Principal? p = Match(cookie);
            if (p != null) return p;
        }
        if (allowQuery && request.Query.TryGetValue("token", out var q))
        {
            return Match(q.ToString());
        }
        return null;
    }

    private static byte[] Hash(string s) => SHA256.HashData(Encoding.UTF8.GetBytes(s));
}
