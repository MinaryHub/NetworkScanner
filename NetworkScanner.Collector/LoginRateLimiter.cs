namespace NetworkScanner.Collector;

// 대시보드 로그인 무차별 대입 방지: 클라이언트 IP별 실패 횟수를 메모리에 세고, 창 안에서 한도를 넘으면 잠시 막는다.
// 단일 프로세스 메모리라 재시작하면 초기화되며, 프록시 뒤에서는 X-Forwarded-For 처리를 프록시/ForwardedHeaders에 맡긴다.
public sealed class LoginRateLimiter
{
    private readonly object _lock = new();
    private readonly Dictionary<string, (int Failures, DateTime WindowStart)> _byClient = new(StringComparer.Ordinal);

    public LoginRateLimiter(int maxFailures = 10, TimeSpan? window = null)
    {
        MaxFailures = Math.Max(1, maxFailures);
        Window = window ?? TimeSpan.FromMinutes(15);
    }

    public int MaxFailures { get; }
    public TimeSpan Window { get; }

    // 한도를 넘었으면 true(로그인 시도 자체를 거절한다).
    public bool IsBlocked(string client, DateTime nowUtc)
    {
        lock (_lock)
        {
            Sweep(nowUtc);
            return _byClient.TryGetValue(client, out var e) && e.Failures >= MaxFailures;
        }
    }

    // 실패를 기록하고 남은 시도 횟수를 돌려준다.
    public int RecordFailure(string client, DateTime nowUtc)
    {
        lock (_lock)
        {
            Sweep(nowUtc);
            if (!_byClient.TryGetValue(client, out var e) || nowUtc - e.WindowStart >= Window)
                e = (0, nowUtc);
            e.Failures++;
            _byClient[client] = e;
            return Math.Max(0, MaxFailures - e.Failures);
        }
    }

    // 성공하면 그 클라이언트의 카운터를 지운다.
    public void Reset(string client)
    {
        lock (_lock) _byClient.Remove(client);
    }

    // 창이 지난 항목을 버려 메모리가 늘지 않게 한다.
    private void Sweep(DateTime nowUtc)
    {
        if (_byClient.Count == 0) return;
        var expired = new List<string>();
        foreach (var (client, e) in _byClient)
            if (nowUtc - e.WindowStart >= Window) expired.Add(client);
        foreach (string c in expired) _byClient.Remove(c);
    }
}
