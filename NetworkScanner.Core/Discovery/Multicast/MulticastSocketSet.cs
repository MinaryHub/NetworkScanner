using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace NetworkScanner.Discovery.Multicast
{
    // SSDP/mDNS 공용 멀티캐스트 소켓 묶음. 멀티캐스트는 "어느 인터페이스로 나가느냐"가 중요하므로
    // 활성 IPv4 인터페이스마다 그 주소에 바인딩한 송신 소켓을 하나씩 만들고(MulticastInterface 지정),
    // 필요하면 그룹 포트(5353 등)에 바인딩한 수신 소켓도 열어 멀티캐스트로 오는 응답까지 받는다.
    // 모든 소켓의 수신 데이터그램은 하나의 채널로 모인다.
    internal sealed class MulticastSocketSet : IDisposable
    {
        public readonly record struct Datagram(IPEndPoint From, byte[] Data);

        public const int MaxDatagramBytes = 9000;

        private readonly IPEndPoint _group;
        private readonly List<UdpClient> _senders = new();
        private readonly List<UdpClient> _all = new();
        private readonly Channel<Datagram> _incoming = Channel.CreateUnbounded<Datagram>(new UnboundedChannelOptions { SingleReader = true });
        private readonly CancellationTokenSource _cts = new();
        private readonly List<Task> _pumps = new();
        private bool _disposed;

        private MulticastSocketSet(IPAddress group, int port) => _group = new IPEndPoint(group, port);

        public int SenderCount => _senders.Count;

        // listenOnGroupPort: 그룹 포트에도 바인딩(ReuseAddress)하고 그룹에 가입해 멀티캐스트 응답을 받는다(mDNS용).
        public static MulticastSocketSet Open(IPAddress group, int port, short ttl, bool listenOnGroupPort)
        {
            var set = new MulticastSocketSet(group, port);
            List<IPAddress> locals = LocalIPv4Addresses();

            foreach (IPAddress addr in locals)
            {
                try
                {
                    var c = new UdpClient(AddressFamily.InterNetwork);
                    c.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                    c.Client.Bind(new IPEndPoint(addr, 0));
                    c.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastInterface, addr.GetAddressBytes());
                    c.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastTimeToLive, (int)ttl);
                    set._senders.Add(c);
                    set._all.Add(c);
                }
                catch
                {
                    // 해당 인터페이스는 건너뛴다.
                }
            }

            // 인터페이스를 하나도 못 열면 기본 경로(0.0.0.0)로라도 보낸다.
            if (set._senders.Count == 0)
            {
                try
                {
                    var c = new UdpClient(new IPEndPoint(IPAddress.Any, 0));
                    c.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastTimeToLive, (int)ttl);
                    set._senders.Add(c);
                    set._all.Add(c);
                }
                catch { }
            }

            if (listenOnGroupPort)
            {
                try
                {
                    var l = new UdpClient(AddressFamily.InterNetwork);
                    // Unix에서는 ReuseAddress가 SO_REUSEPORT까지 켜므로 mDNSResponder/avahi와 포트를 나눠 쓸 수 있다.
                    l.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                    l.Client.Bind(new IPEndPoint(IPAddress.Any, port));
                    bool joined = false;
                    foreach (IPAddress addr in locals)
                    {
                        try { l.JoinMulticastGroup(group, addr); joined = true; } catch { }
                    }
                    if (!joined)
                    {
                        try { l.JoinMulticastGroup(group); } catch { }
                    }
                    set._all.Add(l);
                }
                catch
                {
                    // 포트를 못 잡으면 유니캐스트 응답(QU)만으로 진행한다.
                }
            }

            foreach (UdpClient c in set._all) set._pumps.Add(set.PumpAsync(c));
            return set;
        }

        // 모든 송신 소켓으로 그룹 주소에 보낸다. 실패는 무시한다.
        public async Task SendAsync(byte[] payload, CancellationToken ct)
        {
            foreach (UdpClient c in _senders)
            {
                try { await c.SendAsync(payload, _group, ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { throw; }
                catch { }
            }
        }

        // 채널에서 다음 데이터그램을 꺼낸다. 취소되면 null.
        public async Task<Datagram?> ReceiveAsync(CancellationToken ct)
        {
            try
            {
                return await _incoming.Reader.ReadAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return null;
            }
            catch (ChannelClosedException)
            {
                return null;
            }
        }

        private async Task PumpAsync(UdpClient client)
        {
            int errors = 0;
            while (!_cts.IsCancellationRequested)
            {
                try
                {
                    UdpReceiveResult r = await client.ReceiveAsync(_cts.Token).ConfigureAwait(false);
                    byte[] data = r.Buffer.Length > MaxDatagramBytes ? r.Buffer[..MaxDatagramBytes] : r.Buffer;
                    _incoming.Writer.TryWrite(new Datagram(r.RemoteEndPoint, data));
                }
                catch (OperationCanceledException) { return; }
                catch (ObjectDisposedException) { return; }
                catch (SocketException)
                {
                    // Windows는 ICMP Port Unreachable을 ConnectionReset으로 올린다. 계속 받되 과도하면 멈춘다.
                    if (++errors > 50) return;
                }
                catch { return; }
            }
        }

        // 활성(Up)·비루프백 인터페이스의 IPv4 유니캐스트 주소 목록.
        public static List<IPAddress> LocalIPv4Addresses()
        {
            var list = new List<IPAddress>();
            try
            {
                foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.OperationalStatus != OperationalStatus.Up) continue;
                    if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback || nic.NetworkInterfaceType == NetworkInterfaceType.Tunnel) continue;
                    IPInterfaceProperties props;
                    try { props = nic.GetIPProperties(); } catch { continue; }
                    foreach (UnicastIPAddressInformation u in props.UnicastAddresses)
                    {
                        if (u.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                        if (!list.Contains(u.Address)) list.Add(u.Address);
                    }
                }
            }
            catch { }
            return list;
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            try { _cts.Cancel(); } catch { }
            foreach (UdpClient c in _all)
            {
                try { c.Close(); } catch { }
            }
            _incoming.Writer.TryComplete();
            _cts.Dispose();
        }
    }
}
