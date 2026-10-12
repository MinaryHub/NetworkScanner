using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace NetworkScanner.Discovery.Infrastructure
{
    // SNMP v2c 부분트리 걷기. GETBULK(max-repetitions 25)로 걷다가 에이전트가 bulk에 오류/무응답이면 GETNEXT로 내려간다(SNMPv1류 장비).
    // 반환 OID가 부분트리를 벗어나거나 endOfMibView가 오면 멈추고, 최대 5000행까지만 모은다.
    // 어떤 경우에도 예외를 던지지 않고 그때까지 모은 행을 돌려준다.
    public sealed class SnmpWalker
    {
        public const int DefaultPort = 161;
        public const int MaxRows = 5000;
        public const int MaxRepetitions = 25;
        private const int AttemptsPerRequest = 2;

        private readonly Func<byte[], Task<byte[]?>>? _transport; // 테스트용 가짜 전송(요청 바이트 → 응답 바이트 또는 null=무응답)
        private readonly int _port;
        private int _nextRequestId = Random.Shared.Next(1, 1 << 30);

        public SnmpWalker() : this(DefaultPort) { }

        public SnmpWalker(int port)
        {
            _port = port;
        }

        internal SnmpWalker(Func<byte[], Task<byte[]?>> transport)
        {
            _transport = transport;
            _port = DefaultPort;
        }

        public async Task<IReadOnlyList<(string Oid, byte Type, byte[] Raw, string Text)>> WalkAsync(
            IPAddress agent, string community, string baseOid, int timeoutMs, CancellationToken ct)
        {
            var rows = new List<(string Oid, byte Type, byte[] Raw, string Text)>();
            string root = OidUtil.Normalize(baseOid);
            if (!OidUtil.TryParse(root, out long[] rootArcs) || rootArcs.Length < 2) return rows;
            if (timeoutMs <= 0) return rows;

            // 전체 걷기 상한: 요청당 timeoutMs의 20배(5초~60초). 느린 장비의 큰 테이블이 스캔을 붙잡지 않게 한다.
            using var overall = CancellationTokenSource.CreateLinkedTokenSource(ct);
            overall.CancelAfter(Math.Clamp(timeoutMs * 20, 5_000, 60_000));

            UdpClient? client = null;
            try
            {
                if (_transport == null) client = CreateClient(agent);

                string current = root;
                bool useBulk = true;
                bool firstRequest = true;

                while (rows.Count < MaxRows && !overall.IsCancellationRequested)
                {
                    int requestId = NextRequestId();
                    byte[] request = useBulk
                        ? SnmpBer.BuildGetBulk(community, requestId, current, 0, MaxRepetitions)
                        : SnmpBer.BuildGetNext(community, requestId, current);

                    SnmpBer.Pdu? response = await ExchangeAsync(client, agent, request, requestId, timeoutMs, overall.Token).ConfigureAwait(false);

                    if (response == null)
                    {
                        // 첫 bulk에 아무 응답이 없으면 bulk를 조용히 버리는 장비일 수 있으니 getnext로 한 번 더 시도한다.
                        if (useBulk && firstRequest) { useBulk = false; firstRequest = false; continue; }
                        break;
                    }
                    firstRequest = false;

                    if (response.ErrorStatus != 0)
                    {
                        if (useBulk) { useBulk = false; continue; } // tooBig/genErr → v1류 장비, getnext로 전환
                        break; // getnext의 noSuchName(2) = v1 end-of-mib
                    }
                    if (response.VarBinds.Count == 0) break;

                    bool done = false;
                    foreach (SnmpBer.VarBind vb in response.VarBinds)
                    {
                        if (vb.Tag == SnmpBer.TagEndOfMibView || vb.Tag == SnmpBer.TagNoSuchObject || vb.Tag == SnmpBer.TagNoSuchInstance) { done = true; break; }
                        if (!OidUtil.IsUnder(vb.Oid, root)) { done = true; break; }
                        if (OidUtil.Compare(vb.Oid, current) <= 0) { done = true; break; } // 진행 없음 → 루프 방지
                        rows.Add((vb.Oid, vb.Tag, vb.Raw, SnmpBer.FormatText(vb.Tag, vb.Raw)));
                        current = vb.Oid;
                        if (rows.Count >= MaxRows) { done = true; break; }
                    }
                    if (done) break;
                }
            }
            catch (Exception ex)
            {
                AppLogger.LogDebug(nameof(SnmpWalker), $"{agent} {root} 걷기 중단: {ex.Message}");
            }
            finally
            {
                client?.Dispose();
            }
            return rows;
        }

        // 스칼라 GET. SnmpCodec의 GetRequest/Response 처리를 그대로 쓰고 전송만 공유한다. 응답이 없으면 null.
        public async Task<IReadOnlyDictionary<string, string>?> GetAsync(IPAddress agent, string community, string[] oids, int timeoutMs, CancellationToken ct)
        {
            if (oids.Length == 0 || timeoutMs <= 0) return null;
            UdpClient? client = null;
            try
            {
                if (_transport == null) client = CreateClient(agent);
                int requestId = NextRequestId();
                byte[] request = SnmpCodec.BuildGetRequest(community, requestId, oids);
                Dictionary<string, string>? values = null;

                for (int attempt = 0; attempt < AttemptsPerRequest && values == null; attempt++)
                {
                    ct.ThrowIfCancellationRequested();
                    await SendReceiveAsync(client, agent, request, timeoutMs, data =>
                    {
                        if (!SnmpCodec.TryParseResponse(data, out int id, out var parsed) || id != requestId) return false;
                        values = parsed;
                        return true;
                    }, ct).ConfigureAwait(false);
                    if (_transport != null) break; // 가짜 전송은 재시도 의미 없음
                }
                return values;
            }
            catch (Exception ex)
            {
                AppLogger.LogDebug(nameof(SnmpWalker), $"{agent} GET 실패: {ex.Message}");
                return null;
            }
            finally
            {
                client?.Dispose();
            }
        }

        private int NextRequestId()
        {
            int id = Interlocked.Increment(ref _nextRequestId);
            if (id <= 0) { Interlocked.Exchange(ref _nextRequestId, 1); id = 1; }
            return id;
        }

        private static UdpClient CreateClient(IPAddress agent)
        {
            return new UdpClient(new IPEndPoint(agent.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0));
        }

        // 한 요청을 보내고 요청 ID가 맞는 Response PDU를 돌려준다. 재시도 후에도 없으면 null.
        private async Task<SnmpBer.Pdu?> ExchangeAsync(UdpClient? client, IPAddress agent, byte[] request, int requestId, int timeoutMs, CancellationToken ct)
        {
            SnmpBer.Pdu? result = null;
            for (int attempt = 0; attempt < AttemptsPerRequest && result == null; attempt++)
            {
                if (ct.IsCancellationRequested) return null;
                await SendReceiveAsync(client, agent, request, timeoutMs, data =>
                {
                    if (!SnmpBer.TryParse(data, out SnmpBer.Pdu pdu) || pdu.Type != SnmpBer.PduResponse || pdu.RequestId != requestId) return false;
                    result = pdu;
                    return true;
                }, ct).ConfigureAwait(false);
                if (_transport != null) break;
            }
            return result;
        }

        // 요청 한 번 전송 후 timeoutMs 동안 accept가 true를 돌려주는 데이터그램을 기다린다.
        private async Task SendReceiveAsync(UdpClient? client, IPAddress agent, byte[] request, int timeoutMs, Func<byte[], bool> accept, CancellationToken ct)
        {
            if (_transport != null)
            {
                byte[]? reply = await _transport(request).ConfigureAwait(false);
                if (reply != null) accept(reply);
                return;
            }
            if (client == null) return;

            using var slice = CancellationTokenSource.CreateLinkedTokenSource(ct);
            slice.CancelAfter(timeoutMs);
            try
            {
                await client.SendAsync(request, new IPEndPoint(agent, _port), slice.Token).ConfigureAwait(false);
                while (true)
                {
                    UdpReceiveResult r = await client.ReceiveAsync(slice.Token).ConfigureAwait(false);
                    if (!r.RemoteEndPoint.Address.Equals(agent)) continue;
                    if (accept(r.Buffer)) return;
                }
            }
            catch (OperationCanceledException)
            {
                // 요청 타임아웃 또는 호출자 취소
            }
            catch (SocketException)
            {
                // ICMP port unreachable(Windows는 ConnectionReset) → 닫힌 포트
            }
        }
    }
}
