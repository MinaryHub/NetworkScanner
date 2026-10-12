using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace NetworkScanner.Discovery.Fingerprint
{
    // NTLMSSP(MS-NLMP) NEGOTIATE_MESSAGE 조립과 CHALLENGE_MESSAGE 해석. 인증은 하지 않는다 — 서버가 CHALLENGE에
    // 실어 보내는 OS 버전과 AV_PAIR(컴퓨터/도메인 이름)만 읽는다.
    internal static class NtlmCodec
    {
        public const uint FlagUnicode = 0x00000001;
        public const uint FlagOem = 0x00000002;
        public const uint FlagRequestTarget = 0x00000004;
        public const uint FlagNtlm = 0x00000200;
        public const uint FlagAlwaysSign = 0x00008000;
        public const uint FlagTargetTypeDomain = 0x00010000;
        public const uint FlagTargetTypeServer = 0x00020000;
        public const uint FlagExtendedSessionSecurity = 0x00080000;
        public const uint FlagTargetInfo = 0x00800000;
        public const uint FlagVersion = 0x02000000;
        public const uint Flag128 = 0x20000000;
        public const uint Flag56 = 0x80000000;

        public const uint NegotiateFlags = FlagUnicode | FlagOem | FlagRequestTarget | FlagNtlm | FlagAlwaysSign
                                         | FlagExtendedSessionSecurity | FlagVersion | Flag128 | Flag56;

        public const ushort AvEol = 0x0000;
        public const ushort AvNbComputerName = 0x0001;
        public const ushort AvNbDomainName = 0x0002;
        public const ushort AvDnsComputerName = 0x0003;
        public const ushort AvDnsDomainName = 0x0004;
        public const ushort AvDnsTreeName = 0x0005;
        public const ushort AvFlags = 0x0006;
        public const ushort AvTimestamp = 0x0007;

        private static readonly byte[] Signature = { (byte)'N', (byte)'T', (byte)'L', (byte)'M', (byte)'S', (byte)'S', (byte)'P', 0 };
        private const uint TypeNegotiate = 1, TypeChallenge = 2;

        public readonly record struct Version(byte Major, byte Minor, ushort Build)
        {
            public override string ToString() => $"{Major}.{Minor}.{Build}";
        }

        public sealed class Challenge
        {
            public uint Flags { get; init; }
            public byte[] ServerChallenge { get; init; } = Array.Empty<byte>();
            public string? TargetName { get; init; }
            public Version? Version { get; init; }
            public IReadOnlyList<KeyValuePair<ushort, byte[]>> AvPairs { get; init; } = Array.Empty<KeyValuePair<ushort, byte[]>>();

            public string? NbComputerName => AvString(AvNbComputerName);
            public string? NbDomainName => AvString(AvNbDomainName);
            public string? DnsComputerName => AvString(AvDnsComputerName);
            public string? DnsDomainName => AvString(AvDnsDomainName);
            public string? DnsTreeName => AvString(AvDnsTreeName);

            // 이름이 담긴 AV_PAIR가 하나라도 있는지.
            public bool HasNameAvPairs => NbComputerName != null || NbDomainName != null || DnsComputerName != null || DnsDomainName != null;

            private string? AvString(ushort id)
            {
                foreach (var kv in AvPairs)
                    if (kv.Key == id && kv.Value.Length > 0 && kv.Value.Length % 2 == 0)
                    {
                        string s = Encoding.Unicode.GetString(kv.Value).Trim('\0').Trim();
                        return s.Length == 0 ? null : s;
                    }
                return null;
            }
        }

        // ---------- NEGOTIATE_MESSAGE ----------

        // 도메인/워크스테이션은 비우고 Version만 붙인 40바이트 메시지.
        public static byte[] BuildNegotiateMessage(uint flags = NegotiateFlags)
        {
            var msg = new byte[40];
            Span<byte> s = msg;
            Signature.CopyTo(s);
            BinaryPrimitives.WriteUInt32LittleEndian(s.Slice(8), TypeNegotiate);
            BinaryPrimitives.WriteUInt32LittleEndian(s.Slice(12), flags);
            BinaryPrimitives.WriteUInt32LittleEndian(s.Slice(20), 40);   // DomainName offset(비어 있음)
            BinaryPrimitives.WriteUInt32LittleEndian(s.Slice(28), 40);   // Workstation offset(비어 있음)
            WriteVersion(s.Slice(32), new Version(10, 0, 19045));
            return msg;
        }

        public static bool IsNegotiateMessage(ReadOnlySpan<byte> msg)
            => msg.Length >= 16 && msg.Slice(0, 8).SequenceEqual(Signature) && BinaryPrimitives.ReadUInt32LittleEndian(msg.Slice(8)) == TypeNegotiate;

        // ---------- CHALLENGE_MESSAGE ----------

        public static bool TryParseChallenge(ReadOnlySpan<byte> msg, out Challenge challenge)
        {
            challenge = null!;
            if (msg.Length < 48 || !msg.Slice(0, 8).SequenceEqual(Signature)) return false;
            if (BinaryPrimitives.ReadUInt32LittleEndian(msg.Slice(8)) != TypeChallenge) return false;

            uint flags = BinaryPrimitives.ReadUInt32LittleEndian(msg.Slice(20));
            byte[] serverChallenge = msg.Slice(24, 8).ToArray();
            bool unicode = (flags & FlagUnicode) != 0;

            string? targetName = null;
            if (TryField(msg, 12, out ReadOnlySpan<byte> tn) && tn.Length > 0)
                targetName = (unicode ? Encoding.Unicode.GetString(tn) : Encoding.ASCII.GetString(tn)).Trim('\0').Trim();

            Version? version = null;
            if ((flags & FlagVersion) != 0 && msg.Length >= 56)
            {
                var v = new Version(msg[48], msg[49], BinaryPrimitives.ReadUInt16LittleEndian(msg.Slice(50)));
                if (v.Major != 0) version = v;
            }

            var pairs = new List<KeyValuePair<ushort, byte[]>>();
            if ((flags & FlagTargetInfo) != 0 && TryField(msg, 40, out ReadOnlySpan<byte> ti))
            {
                int pos = 0;
                while (pos + 4 <= ti.Length)
                {
                    ushort id = BinaryPrimitives.ReadUInt16LittleEndian(ti.Slice(pos));
                    int len = BinaryPrimitives.ReadUInt16LittleEndian(ti.Slice(pos + 2));
                    pos += 4;
                    if (id == AvEol) break;
                    if (pos + len > ti.Length) break;
                    pairs.Add(new KeyValuePair<ushort, byte[]>(id, ti.Slice(pos, len).ToArray()));
                    pos += len;
                }
            }

            challenge = new Challenge
            {
                Flags = flags,
                ServerChallenge = serverChallenge,
                TargetName = string.IsNullOrEmpty(targetName) ? null : targetName,
                Version = version,
                AvPairs = pairs,
            };
            return true;
        }

        // (Len, MaxLen, Offset) 필드 묘사자를 따라 본문 조각을 얻는다.
        private static bool TryField(ReadOnlySpan<byte> msg, int fieldOffset, out ReadOnlySpan<byte> data)
        {
            data = default;
            int len = BinaryPrimitives.ReadUInt16LittleEndian(msg.Slice(fieldOffset));
            long off = BinaryPrimitives.ReadUInt32LittleEndian(msg.Slice(fieldOffset + 4));
            if (len == 0) { data = ReadOnlySpan<byte>.Empty; return true; }
            if (off < 0 || off + len > msg.Length) return false;
            data = msg.Slice((int)off, len);
            return true;
        }

        // 서버 역할(테스트/루프백)용 CHALLENGE_MESSAGE. version이 null이면 NEGOTIATE_VERSION 플래그 없이 0으로 채운다.
        public static byte[] BuildChallengeMessage(string targetName, Version? version, IEnumerable<KeyValuePair<ushort, string>> avPairs, byte[]? serverChallenge = null)
        {
            byte[] target = Encoding.Unicode.GetBytes(targetName ?? "");
            var ti = new List<byte>();
            foreach (var kv in avPairs)
            {
                byte[] v = Encoding.Unicode.GetBytes(kv.Value);
                ti.AddRange(BitConverter.GetBytes(kv.Key));
                ti.AddRange(BitConverter.GetBytes((ushort)v.Length));
                ti.AddRange(v);
            }
            ti.AddRange(new byte[4]);   // MsvAvEOL
            byte[] targetInfo = ti.ToArray();

            uint flags = FlagUnicode | FlagRequestTarget | FlagNtlm | FlagAlwaysSign | FlagTargetTypeServer
                       | FlagExtendedSessionSecurity | FlagTargetInfo | Flag128 | Flag56;
            if (version != null) flags |= FlagVersion;

            var msg = new byte[56 + target.Length + targetInfo.Length];
            Span<byte> s = msg;
            Signature.CopyTo(s);
            BinaryPrimitives.WriteUInt32LittleEndian(s.Slice(8), TypeChallenge);
            BinaryPrimitives.WriteUInt16LittleEndian(s.Slice(12), (ushort)target.Length);
            BinaryPrimitives.WriteUInt16LittleEndian(s.Slice(14), (ushort)target.Length);
            BinaryPrimitives.WriteUInt32LittleEndian(s.Slice(16), 56);
            BinaryPrimitives.WriteUInt32LittleEndian(s.Slice(20), flags);
            (serverChallenge ?? new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }).AsSpan(0, 8).CopyTo(s.Slice(24));
            BinaryPrimitives.WriteUInt16LittleEndian(s.Slice(40), (ushort)targetInfo.Length);
            BinaryPrimitives.WriteUInt16LittleEndian(s.Slice(42), (ushort)targetInfo.Length);
            BinaryPrimitives.WriteUInt32LittleEndian(s.Slice(44), (uint)(56 + target.Length));
            if (version != null) WriteVersion(s.Slice(48), version.Value);
            target.CopyTo(s.Slice(56));
            targetInfo.CopyTo(s.Slice(56 + target.Length));
            return msg;
        }

        private static void WriteVersion(Span<byte> s, Version v)
        {
            s[0] = v.Major;
            s[1] = v.Minor;
            BinaryPrimitives.WriteUInt16LittleEndian(s.Slice(2), v.Build);
            s[4] = s[5] = s[6] = 0;
            s[7] = 0x0F;   // NTLMSSP_REVISION_W2K3
        }

        // ---------- Windows 버전 이름 ----------

        // NTLM Version → 사람이 읽는 Windows 이름. 10.0은 빌드로 구분(22000 이상 = 11), 그 외는 major.minor로.
        // 14393/17763은 같은 빌드의 Windows 10 LTSB/LTSC 클라이언트일 수도 있지만 서버 쪽 이름을 쓴다.
        public static string WindowsVersionName(int major, int minor, int build)
        {
            if (major == 10 && minor == 0)
            {
                if (build == 26100) return "Windows 11 / Server 2025 (10.0.26100)";
                if (build >= 22000) return $"Windows 11 (10.0.{build})";
                if (build == 20348) return "Windows Server 2022 (10.0.20348)";
                if (build == 17763) return "Windows Server 2019 (10.0.17763)";
                if (build == 14393) return "Windows Server 2016 (10.0.14393)";
                return $"Windows 10 (10.0.{build})";
            }
            if (major == 6)
            {
                switch (minor)
                {
                    case 3: return "Windows 8.1 (6.3)";
                    case 2: return "Windows 8 (6.2)";
                    case 1: return "Windows 7 (6.1)";
                    case 0: return "Windows Vista (6.0)";
                }
            }
            if (major == 5)
            {
                switch (minor)
                {
                    case 2: return "Windows Server 2003 (5.2)";
                    case 1: return "Windows XP (5.1)";
                    case 0: return "Windows 2000 (5.0)";
                }
            }
            return string.Format(CultureInfo.InvariantCulture, "Windows NT {0}.{1}.{2}", major, minor, build);
        }
    }
}
