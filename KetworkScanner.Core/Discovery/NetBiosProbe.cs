using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace KetworkScanner.Discovery
{
    // NetBIOS NBSTAT(노드 상태) 질의로 Windows/Samba 호스트의 컴퓨터 이름, 작업그룹/도메인, 어댑터 MAC을 얻는다.
    public sealed class NetBiosProbe : IIdentityProbe
    {
        public const int DefaultPort = 137;
        private const string ZeroMac = "00:00:00:00:00:00";

        private readonly int _port;

        public NetBiosProbe() : this(DefaultPort) { }

        internal NetBiosProbe(int port) => _port = port;

        public string Name => HostIdentity.SourceNetBios;

        public async Task<HostIdentity?> ProbeAsync(IPAddress ip, int timeoutMs, CancellationToken ct)
        {
            try
            {
                ushort id = (ushort)Random.Shared.Next(1, ushort.MaxValue);
                byte[] request = NetBiosCodec.BuildNodeStatusRequest(id);
                List<NetBiosCodec.NameEntry>? names = null;
                string? mac = null;

                byte[]? reply = await UdpExchange.SendReceiveAsync(ip, _port, request, timeoutMs, attempts: 1, data =>
                {
                    if (!NetBiosCodec.TryParseNodeStatusResponse(data, out ushort rid, out var parsed, out string? m) || rid != id)
                        return false;
                    names = parsed;
                    mac = m;
                    return true;
                }, ct).ConfigureAwait(false);

                if (reply == null || names == null) return null;
                return FromNames(names, mac);
            }
            catch
            {
                return null;
            }
        }

        internal static HostIdentity? FromNames(IReadOnlyList<NetBiosCodec.NameEntry> names, string? mac)
        {
            string? host = null, workgroup = null;
            var services = new List<string>();
            bool domainController = false;
            foreach (var n in names)
            {
                if (n.Suffix == 0x00)
                {
                    if (!n.IsGroup) host ??= n.Name;
                    else workgroup ??= n.Name;
                }
                else if (n.Suffix == 0x20 && !n.IsGroup)
                {
                    host ??= n.Name;      // 파일 서버 서비스 이름 = 컴퓨터 이름
                }
                else if (n.Suffix == 0x1B || n.Suffix == 0x1C)
                {
                    domainController = true;
                    workgroup ??= n.Name;
                }
                services.Add(n.Suffix.ToString("X2", CultureInfo.InvariantCulture));
            }
            if (host == null) return null;

            var attrs = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [HostIdentity.AttrNetBiosName] = host,
            };
            if (workgroup != null) attrs[HostIdentity.AttrNetBiosWorkgroup] = workgroup;
            bool samba = mac == ZeroMac;
            if (mac != null && !samba) attrs[HostIdentity.AttrNetBiosMac] = mac;
            if (services.Count > 0) attrs["netbios.services"] = string.Join(",", services);
            if (domainController) attrs["netbios.domaincontroller"] = "true";

            // Samba(nmbd)는 UNIT_ID를 0으로 채우므로 Windows라고 단정하지 않는다.
            string osHint = samba ? "Windows/SMB" : "Windows";
            string? deviceHint = domainController ? "domain controller" : samba ? "smb server" : null;
            string description = workgroup != null ? $"NetBIOS: {host} ({workgroup})" : $"NetBIOS: {host}";
            return new HostIdentity(HostIdentity.SourceNetBios, host, description, osHint, deviceHint, attrs);
        }
    }
}
