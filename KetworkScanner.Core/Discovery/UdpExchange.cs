using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace KetworkScanner.Discovery
{
    // 프로브 공통 UDP 왕복: 임의 포트에 바인딩해 요청 데이터그램을 보내고, 대상 주소에서 온 첫 번째 "수락된" 응답을
    // 돌려준다. 전체 timeoutMs 안에서 attempts회까지 재전송하며, 다른 주소에서 온 패킷은 무시한다.
    // transport가 주어지면 소켓 대신 그것을 쓴다(테스트용 가짜 전송: 요청 바이트 → 응답 바이트 또는 null=무응답, 재시도 없음).
    internal static class UdpExchange
    {
        // 파싱 상한. 이보다 긴 데이터그램은 앞부분만 넘긴다.
        public const int MaxDatagramBytes = 4096;

        public static async Task<byte[]?> SendReceiveAsync(IPAddress ip, int port, byte[] request, int timeoutMs,
            int attempts, Func<byte[], bool> accept, CancellationToken ct, Func<byte[], Task<byte[]?>>? transport = null)
        {
            if (timeoutMs <= 0 || attempts <= 0) return null;
            if (transport != null)
            {
                ct.ThrowIfCancellationRequested();
                byte[]? reply = await transport(request).ConfigureAwait(false);
                return reply != null && accept(reply) ? reply : null;
            }

            using var overall = CancellationTokenSource.CreateLinkedTokenSource(ct);
            overall.CancelAfter(timeoutMs);

            using var client = new UdpClient(new IPEndPoint(
                ip.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0));
            var target = new IPEndPoint(ip, port);
            int perAttemptMs = Math.Max(1, timeoutMs / attempts);

            try
            {
                for (int attempt = 0; attempt < attempts; attempt++)
                {
                    await client.SendAsync(request, target, overall.Token).ConfigureAwait(false);

                    // 마지막 시도는 전체 마감까지 기다리고, 그 전 시도는 분할 마감이 지나면 재전송한다.
                    using var slice = CancellationTokenSource.CreateLinkedTokenSource(overall.Token);
                    if (attempt < attempts - 1) slice.CancelAfter(perAttemptMs);
                    try
                    {
                        while (true)
                        {
                            UdpReceiveResult r = await client.ReceiveAsync(slice.Token).ConfigureAwait(false);
                            if (!r.RemoteEndPoint.Address.Equals(ip)) continue;
                            byte[] data = r.Buffer.Length > MaxDatagramBytes ? r.Buffer[..MaxDatagramBytes] : r.Buffer;
                            if (accept(data)) return data;
                        }
                    }
                    catch (OperationCanceledException) when (!overall.IsCancellationRequested)
                    {
                        // 분할 마감 — 재전송
                    }
                }
            }
            catch (OperationCanceledException)
            {
                // 전체 타임아웃 또는 호출자 취소
            }
            catch (SocketException)
            {
                // Windows는 ICMP Port Unreachable을 ConnectionReset으로 올린다 → 닫힌 포트
            }
            return null;
        }
    }
}
