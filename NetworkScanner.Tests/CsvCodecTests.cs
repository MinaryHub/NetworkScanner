using System.Collections.Generic;
using NetworkScanner;

namespace NetworkScanner.Tests
{
    public class CsvCodecTests
    {
        [Fact]
        public void FormatLine_QuotesFieldsContainingCommaQuoteOrNewline()
        {
            string line = CsvCodec.FormatLine(new[] { "plain", "a,b", "say \"hi\"", "line1\nline2", "" });

            Assert.Equal("plain,\"a,b\",\"say \"\"hi\"\"\",\"line1\nline2\",", line);
        }

        [Fact]
        public void Parse_RoundTripsFieldsWithCommasQuotesAndNewlines()
        {
            var original = new[] { "10.0.0.1", "22/80", "Printer, 3F", "note \"x\"", "multi\r\nline" };
            string text = CsvCodec.FormatLine(original) + "\r\n";

            List<string[]> rows = CsvCodec.Parse(text);

            Assert.Single(rows);
            Assert.Equal(original, rows[0]);
        }

        [Fact]
        public void Parse_SkipsBlankLinesAndHandlesMissingTrailingNewline()
        {
            List<string[]> rows = CsvCodec.Parse("a,b\n\nc,d");

            Assert.Equal(2, rows.Count);
            Assert.Equal(new[] { "a", "b" }, rows[0]);
            Assert.Equal(new[] { "c", "d" }, rows[1]);
        }

        [Theory]
        [InlineData("=1+1", "'=1+1")]
        [InlineData("+cmd", "'+cmd")]
        [InlineData("@SUM", "'@SUM")]
        [InlineData("-cmd", "'-cmd")]
        [InlineData("-12", "-12")]       // 음수는 수식이 아니다
        [InlineData("normal", "normal")]
        public void GuardFormula_PrefixesDangerousLeadingCharacters(string input, string expected)
        {
            Assert.Equal(expected, CsvCodec.GuardFormula(input));
            Assert.Equal(input, CsvCodec.Unguard(CsvCodec.GuardFormula(input)));
        }

        [Fact]
        public void Parse_LegacyUnquotedLine_StillParses()
        {
            // 이전 버전이 남긴 따옴표 없는 단순 CSV도 그대로 읽혀야 한다.
            List<string[]> rows = CsvCodec.Parse("IPAddress,Port,SystemName\n192.168.0.1,22/80/,host1\n");

            Assert.Equal(2, rows.Count);
            Assert.Equal("host1", rows[1][2]);
        }
    }
}
