using System.Buffers.Binary;
using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace NetworkScanner.Platform
{
    // iphlpapi 의 GetIpNetTable2(AF_INET) 로 이웃(ARP) 테이블을 읽어 MAC을 조회한다.
    //
    // MIB_IPNET_TABLE2 = { uint NumEntries; (8바이트 정렬 패딩) MIB_IPNET_ROW2 Table[] }
    // MIB_IPNET_ROW2 (x64, 88바이트):
    //   @0  SOCKADDR_INET Address (28): si_family u16, sin_port u16, sin_addr 4바이트 @4
    //   @28 uint InterfaceIndex
    //   @32 NET_LUID (u64)
    //   @40 byte[32] PhysicalAddress
    //   @72 uint PhysicalAddressLength
    //   @76 int State (NL_NEIGHBOR_STATE)
    //   @80 비트 플래그(IsRouter/IsUnreachable)
    //   @84 uint ReachabilityTime
    // 구조체 패킹 실수를 피하기 위해 명시적 오프셋으로 읽는다.
    [SupportedOSPlatform("windows")]
    public sealed class WindowsIpNetTableArpResolver : IArpResolver
    {
        internal const int RowSize = 88;
        private const int TableHeaderSize = 8; // NumEntries(4) + 패딩(4)

        private const int OffFamily = 0;
        private const int OffSinAddr = 4;
        private const int OffPhysicalAddress = 40;
        private const int OffPhysicalAddressLength = 72;
        private const int OffState = 76;

        private const ushort AfInet = 2;

        // NL_NEIGHBOR_STATE
        private const int StateUnreachable = 0;
        private const int StateIncomplete = 1;
        private const int StateReachable = 2;
        private const int StatePermanent = 6;

        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        private static extern int GetIpNetTable2(ushort family, out IntPtr table);

        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        private static extern void FreeMibTable(IntPtr memory);

        public string? Resolve(string ipv4)
        {
            IntPtr table = IntPtr.Zero;
            try
            {
                if (!IPAddress.TryParse(ipv4, out IPAddress? addr) || addr.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                    return null;
                byte[] target = addr.GetAddressBytes();

                if (GetIpNetTable2(AfInet, out table) != 0 || table == IntPtr.Zero) return null;

                uint count = (uint)Marshal.ReadInt32(table);
                byte[] row = new byte[RowSize];
                for (uint i = 0; i < count; i++)
                {
                    IntPtr rowPtr = table + TableHeaderSize + (int)(i * RowSize);
                    Marshal.Copy(rowPtr, row, 0, RowSize);

                    string? mac = ParseRow(row, target);
                    if (mac != null) return mac;
                }
                return null;
            }
            catch
            {
                return null;
            }
            finally
            {
                if (table != IntPtr.Zero)
                {
                    try { FreeMibTable(table); } catch { }
                }
            }
        }

        // 88바이트 행 하나를 해석해 targetIp(4바이트) 와 일치하고 유효 상태이면 MAC을 반환한다. 테스트용으로 분리.
        internal static string? ParseRow(ReadOnlySpan<byte> row, ReadOnlySpan<byte> targetIp)
        {
            if (row.Length < RowSize || targetIp.Length != 4) return null;

            ushort family = BinaryPrimitives.ReadUInt16LittleEndian(row.Slice(OffFamily, 2));
            if (family != AfInet) return null;

            if (!row.Slice(OffSinAddr, 4).SequenceEqual(targetIp)) return null;

            int state = BinaryPrimitives.ReadInt32LittleEndian(row.Slice(OffState, 4));
            // Reachable(2)/Stale(3)/Delay(4)/Probe(5)/Permanent(6) 만 유효. Unreachable(0)/Incomplete(1) 제외.
            if (state == StateUnreachable || state == StateIncomplete || state < StateReachable || state > StatePermanent)
                return null;

            uint physLen = BinaryPrimitives.ReadUInt32LittleEndian(row.Slice(OffPhysicalAddressLength, 4));
            if (physLen != 6) return null;

            return MacFormat.FromBytes(row.Slice(OffPhysicalAddress, 6));
        }
    }
}
