using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;

namespace NetworkScanner.Discovery
{
    public enum Confidence { Low = 1, Medium = 2, High = 3 }

    // 한 호스트에 대해 어떤 프로브가 어떤 값을 어느 정도 확신으로 알려줬는지. 같은 필드에 여러 출처가 있으면 Best()가 고른다.
    public sealed record Fact(string Field, string Value, string Source, Confidence Confidence)
    {
        public override string ToString() => $"{Field}={Value} ({Source}, {Confidence})";
    }

    // 필드 이름 상수. 프로브와 UI가 같은 문자열을 쓰도록 한다.
    public static class FactFields
    {
        public const string Name = "name";            // 호스트/장비 이름
        public const string Os = "os";                // OS 계열(Windows, Linux, iOS …)
        public const string OsVersion = "osVersion";  // 상세 버전(Windows 10.0.19045, Ubuntu 24.04 …)
        public const string Vendor = "vendor";        // 제조사
        public const string Model = "model";          // 모델명(MacBookPro18,3, RT-AX88U …)
        public const string DeviceType = "deviceType";// 장비 종류(router, printer, nas, camera, phone …)
        public const string Mac = "mac";
        public const string Domain = "domain";        // AD 도메인/워크그룹
        public const string Service = "service";      // 서비스/제품(배너)
        public const string SwitchPort = "switchPort";// 스위치 이름/포트(LLDP/FDB)
        public const string Serial = "serial";
        public const string Ipv6 = "ipv6";
        public const string Description = "description";
    }

    public sealed class HostFacts
    {
        private readonly List<Fact> _facts = new();
        public string Ip { get; }
        public IReadOnlyList<Fact> All => _facts;

        public HostFacts(string ip) { Ip = ip; }

        public void Add(string field, string? value, string source, Confidence confidence)
        {
            if (string.IsNullOrWhiteSpace(value)) return;
            string v = value.Trim();
            // 같은 출처·필드·값은 한 번만.
            if (_facts.Any(f => f.Field == field && f.Source == source && f.Value == v)) return;
            _facts.Add(new Fact(field, v, source, confidence));
        }

        public void AddRange(IEnumerable<Fact> facts)
        {
            foreach (Fact f in facts) Add(f.Field, f.Value, f.Source, f.Confidence);
        }

        // 가장 확신 높은 값(동률이면 먼저 들어온 것).
        public Fact? Best(string field) => _facts.Where(f => f.Field == field).OrderByDescending(f => (int)f.Confidence).FirstOrDefault();
        public string BestValue(string field) => Best(field)?.Value ?? "";
        public IEnumerable<Fact> Of(string field) => _facts.Where(f => f.Field == field);

        public string ToJson() => JsonSerializer.Serialize(_facts, JsonOptions);

        public static HostFacts FromJson(string ip, string? json)
        {
            var facts = new HostFacts(ip);
            if (string.IsNullOrWhiteSpace(json)) return facts;
            try
            {
                var list = JsonSerializer.Deserialize<List<Fact>>(json, JsonOptions);
                if (list != null) facts.AddRange(list);
            }
            catch { }
            return facts;
        }

        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() },
        };
    }

    // 호스트 한 대를 대상으로 하는 핑거프린트 프로브(SMB/SSH/HTTP/UDP 등). 사실(Fact) 목록을 돌려준다.
    public interface IFactProbe
    {
        string Name { get; }
        // 열린 포트 목록을 보고 할 일이 없으면 빈 목록을 바로 돌려준다.
        System.Threading.Tasks.Task<IReadOnlyList<Fact>> ProbeAsync(string ip, IReadOnlyList<int> openPorts, int timeoutMs, System.Threading.CancellationToken ct);
    }

    // 네트워크 전체를 대상으로 한 번 수행하는 발견(SSDP/mDNS 브라우징, 라우터 테이블 등). IP별 사실 목록을 돌려준다.
    public interface INetworkDiscovery
    {
        string Name { get; }
        System.Threading.Tasks.Task<IReadOnlyDictionary<string, IReadOnlyList<Fact>>> DiscoverAsync(int timeoutMs, System.Threading.CancellationToken ct);
    }

    // 스캔 대역(대상 IP 목록)을 알아야 동작하는 발견(능동 ARP 등). 엔진은 스캔마다 그 스캔의 대상 목록을 넘긴다.
    public interface ITargetedNetworkDiscovery : INetworkDiscovery
    {
        System.Threading.Tasks.Task<IReadOnlyDictionary<string, IReadOnlyList<Fact>>> DiscoverAsync(
            IReadOnlyList<System.Net.IPAddress> targets, int timeoutMs, System.Threading.CancellationToken ct);
    }
}
