using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace NetworkScanner.Discovery
{
    // 호스트에 직접(유니캐스트) mDNS 질의를 보내 역방향 PTR(d.c.b.a.in-addr.arpa)을 묻는다. QU 비트를 켜서
    // 응답도 유니캐스트로 받으므로 멀티캐스트 그룹 가입이 필요 없다. Apple/Linux(avahi)/프린터/IoT가 주로 답한다.
    public sealed class MdnsProbe : IIdentityProbe
    {
        public const int DefaultPort = 5353;

        private readonly int _port;

        public MdnsProbe() : this(DefaultPort) { }

        internal MdnsProbe(int port) => _port = port;

        public string Name => HostIdentity.SourceMdns;

        public async Task<HostIdentity?> ProbeAsync(IPAddress ip, int timeoutMs, CancellationToken ct)
        {
            try
            {
                if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return null;
                string reverse = DnsCodec.ReverseName(ip);
                ushort id = (ushort)Random.Shared.Next(1, ushort.MaxValue);
                byte[] query = DnsCodec.BuildQuery(id, reverse, DnsCodec.TypePtr, DnsCodec.ClassInUnicast);
                DnsCodec.Response? response = null;

                byte[]? reply = await UdpExchange.SendReceiveAsync(ip, _port, query, timeoutMs, attempts: 1, data =>
                {
                    // 일부 mDNS 응답기는 ID를 0으로 비운 채 답하므로 ID 일치 또는 0을 허용한다.
                    if (!DnsCodec.TryParseResponse(data, out var parsed) || !parsed.IsResponse) return false;
                    if (parsed.Id != id && parsed.Id != 0) return false;
                    response = parsed;
                    return true;
                }, ct).ConfigureAwait(false);

                if (reply == null || response == null) return null;
                return FromResponse(response, reverse);
            }
            catch
            {
                return null;
            }
        }

        internal static HostIdentity? FromResponse(DnsCodec.Response response, string reverseName)
        {
            // 질의한 역방향 이름에 대한 PTR을 우선하고, 없으면 첫 PTR을 쓴다.
            DnsCodec.Record? ptr = null;
            foreach (var r in response.Answers)
            {
                if (r.Type != DnsCodec.TypePtr || r.Data.Length == 0) continue;
                if (string.Equals(r.Name, reverseName, StringComparison.OrdinalIgnoreCase)) { ptr = r; break; }
                ptr ??= r;
            }
            if (ptr == null) return null;
            string hostName = ptr.Data;

            string shortName = StripLocal(hostName);
            var attrs = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [HostIdentity.AttrMdnsName] = shortName,
                ["mdns.fqdn"] = hostName,
            };

            string? deviceHint = null;
            foreach (var r in CollectAll(response))
            {
                switch (r.Type)
                {
                    case DnsCodec.TypeA:
                        attrs.TryAdd("mdns.address", r.Data);
                        break;
                    case DnsCodec.TypeAaaa:
                        attrs.TryAdd("mdns.address6", r.Data);
                        break;
                    case DnsCodec.TypeTxt:
                        attrs.TryAdd("mdns.txt", r.Data);
                        foreach (string kv in r.Data.Split(';'))
                        {
                            int eq = kv.IndexOf('=');
                            if (eq <= 0) continue;
                            string key = kv.Substring(0, eq).Trim().ToLowerInvariant();
                            string val = kv.Substring(eq + 1).Trim();
                            if (key == "model" && val.Length > 0)
                            {
                                attrs.TryAdd("model", val);
                                deviceHint ??= val;
                            }
                            else if (key == "osxvers" && val.Length > 0)
                            {
                                attrs.TryAdd("mdns.osxvers", val);
                            }
                        }
                        break;
                }
            }

            string? osHint = attrs.ContainsKey("mdns.osxvers") ? "macOS" : null;
            return new HostIdentity(HostIdentity.SourceMdns, shortName, "mDNS: " + hostName, osHint, deviceHint, attrs);
        }

        private static IEnumerable<DnsCodec.Record> CollectAll(DnsCodec.Response r)
        {
            foreach (var x in r.Answers) yield return x;
            foreach (var x in r.Authority) yield return x;
            foreach (var x in r.Additional) yield return x;
        }

        internal static string StripLocal(string name)
        {
            string n = name.TrimEnd('.');
            if (n.EndsWith(".local", StringComparison.OrdinalIgnoreCase)) n = n.Substring(0, n.Length - 6);
            return n;
        }
    }
}
