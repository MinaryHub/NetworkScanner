using System;
using System.Net;
using System.Net.Sockets;

namespace NetworkScanner
{
    // 지정한 MAC 주소로 Wake-on-LAN 매직 패킷을 보내 대상 PC를 원격으로 켠다.
    public static class WakeOnLan
    {
        public static Action<string>? OnError { get; set; }

        // 매직 패킷 = 0xFF 6바이트 + 대상 MAC(6바이트) 16회 반복 = 102바이트.
        public static byte[]? BuildMagicPacket(string mac)
        {
            byte[]? macBytes = ParseMac(mac);
            if (macBytes == null) return null;

            var packet = new byte[6 + 16 * 6];
            for (int i = 0; i < 6; i++) packet[i] = 0xFF;
            for (int i = 0; i < 16; i++) Array.Copy(macBytes, 0, packet, 6 + i * 6, 6);
            return packet;
        }

        public static bool Send(string mac)
        {
            byte[]? packet = BuildMagicPacket(mac);
            if (packet == null)
            {
                OnError?.Invoke(string.Format(Localization.T("wol.invalidmac"), mac));
                return false;
            }

            try
            {
                using var client = new UdpClient { EnableBroadcast = true };
                // WOL 표준 포트(9). 브로드캐스트로 보내 같은 서브넷의 대상에 도달하게 한다.
                client.Send(packet, packet.Length, new IPEndPoint(IPAddress.Broadcast, 9));
                return true;
            }
            catch (Exception ex)
            {
                OnError?.Invoke(string.Format(Localization.T("wol.sendfailed"), ex.Message));
                return false;
            }
        }

        private static byte[]? ParseMac(string mac)
        {
            if (string.IsNullOrWhiteSpace(mac)) return null;

            string[] parts = mac.Split(':', '-');
            if (parts.Length != 6) return null;

            var bytes = new byte[6];
            for (int i = 0; i < 6; i++)
            {
                if (!byte.TryParse(parts[i], System.Globalization.NumberStyles.HexNumber, null, out bytes[i]))
                    return null;
            }
            return bytes;
        }
    }
}
