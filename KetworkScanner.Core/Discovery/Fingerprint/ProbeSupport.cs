using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace KetworkScanner.Discovery.Fingerprint
{
    // 프로브 공통: 출처(Source)가 고정된 Fact 목록. 같은 필드·값은 한 번만 넣는다.
    internal sealed class FactList
    {
        private readonly List<Fact> _facts = new();
        private readonly string _source;

        public FactList(string source) => _source = source;

        public int Count => _facts.Count;

        public void Add(string field, string? value, Confidence confidence)
        {
            if (string.IsNullOrWhiteSpace(value)) return;
            string v = value.Trim();
            foreach (Fact f in _facts)
                if (f.Field == field && string.Equals(f.Value, v, StringComparison.Ordinal)) return;
            _facts.Add(new Fact(field, v, _source, confidence));
        }

        public bool Has(string field)
        {
            foreach (Fact f in _facts) if (f.Field == field) return true;
            return false;
        }

        public IReadOnlyList<Fact> ToList() => _facts.ToArray();
    }

    // TCP 프로브 공통 도우미: 타임아웃이 묶인 토큰, 연결, 정확한 길이 읽기.
    internal static class ProbeTcp
    {
        public static readonly IReadOnlyList<Fact> Empty = Array.Empty<Fact>();

        // 호출자 토큰과 timeoutMs 상한을 하나로 묶는다.
        public static CancellationTokenSource Linked(CancellationToken ct, int timeoutMs)
        {
            var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(Math.Max(100, timeoutMs));
            return cts;
        }

        public static async Task<TcpClient?> ConnectAsync(string ip, int port, CancellationToken ct)
        {
            if (!IPAddress.TryParse(ip, out IPAddress? addr)) return null;
            var client = new TcpClient(addr.AddressFamily) { NoDelay = true };
            try
            {
                await client.ConnectAsync(addr, port, ct).ConfigureAwait(false);
                return client;
            }
            catch
            {
                client.Dispose();
                return null;
            }
        }

        // count 바이트를 다 읽으면 true, 그 전에 끊기면 false.
        public static async Task<bool> ReadExactAsync(Stream stream, byte[] buffer, int count, CancellationToken ct)
        {
            int read = 0;
            while (read < count)
            {
                int n = await stream.ReadAsync(buffer.AsMemory(read, count - read), ct).ConfigureAwait(false);
                if (n <= 0) return false;
                read += n;
            }
            return true;
        }
    }
}
