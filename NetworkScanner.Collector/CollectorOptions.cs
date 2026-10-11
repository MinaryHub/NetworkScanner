namespace NetworkScanner.Collector;

// appsettings.json / 환경 변수(COLLECTOR__TOKENS__0__TOKEN 등)의 "Collector" 섹션.
public sealed class CollectorOptions
{
    public const string SectionName = "Collector";

    // 업로드 파일과 collector.db가 놓이는 루트. 상대 경로는 콘텐츠 루트 기준이다.
    public string DataDir { get; set; } = "./collector-data";

    // 토큰 하나가 사이트 하나를 식별한다.
    public List<TokenEntry> Tokens { get; set; } = new();

    // 모든 사이트를 읽을 수 있는 관리 토큰(선택).
    public string? AdminToken { get; set; }

    public int MaxUploadMb { get; set; } = 50;

    // 사이트별로 보관하는 스캔 수(초과분은 호스트 행과 함께 삭제).
    public int ScansPerSite { get; set; } = 200;

    public long MaxUploadBytes => (long)Math.Max(1, MaxUploadMb) * 1024 * 1024;

    public static CollectorOptions Load(IConfiguration configuration, string contentRoot)
    {
        var o = configuration.GetSection(SectionName).Get<CollectorOptions>() ?? new CollectorOptions();
        o.Tokens ??= new List<TokenEntry>();
        if (string.IsNullOrWhiteSpace(o.DataDir)) o.DataDir = "./collector-data";
        o.DataDir = Path.GetFullPath(Path.IsPathRooted(o.DataDir) ? o.DataDir : Path.Combine(contentRoot, o.DataDir));
        return o;
    }

    // 시작 가능 여부. 문제가 있으면 사람이 읽을 수 있는 메시지를 돌려준다.
    public string? Validate()
    {
        if (Tokens.Count == 0)
            return "no tokens configured. Add Collector:Tokens (e.g. COLLECTOR__TOKENS__0__TOKEN / COLLECTOR__TOKENS__0__SITE) and restart.";
        for (int i = 0; i < Tokens.Count; i++)
        {
            TokenEntry t = Tokens[i];
            if (string.IsNullOrWhiteSpace(t.Token)) return $"Collector:Tokens:{i}:Token is empty.";
            if (t.Token.Trim().Length < 16) return $"Collector:Tokens:{i}:Token is too short (use at least 16 characters).";
            if (string.IsNullOrWhiteSpace(t.Site)) return $"Collector:Tokens:{i}:Site is empty.";
        }
        if (AdminToken != null && AdminToken.Trim().Length > 0 && AdminToken.Trim().Length < 16)
            return "Collector:AdminToken is too short (use at least 16 characters).";
        if (MaxUploadMb < 1) return "Collector:MaxUploadMb must be at least 1.";
        return null;
    }
}

public sealed class TokenEntry
{
    public string Token { get; set; } = "";
    public string Site { get; set; } = "";
}
