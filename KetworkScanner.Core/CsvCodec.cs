using System;
using System.Collections.Generic;
using System.Text;

namespace KetworkScanner
{
    // RFC 4180 CSV 인코더/디코더. 스캔 결과 CSV의 필드에 쉼표·따옴표·개행이 들어가도 열이 밀리지 않게 하고,
    // Excel 등에서 수식으로 실행될 수 있는 값(=, +, -, @, 탭, CR로 시작)은 앞에 작은따옴표를 붙여 무력화한다.
    public static class CsvCodec
    {
        // 한 줄(레코드)을 만든다. 필드마다 필요한 경우에만 따옴표로 감싼다.
        public static string FormatLine(IEnumerable<string?> fields)
        {
            var sb = new StringBuilder();
            bool first = true;
            foreach (string? field in fields)
            {
                if (!first) sb.Append(',');
                first = false;
                sb.Append(Escape(field));
            }
            return sb.ToString();
        }

        public static string Escape(string? value)
        {
            string s = GuardFormula(value ?? "");
            if (s.IndexOfAny(new[] { ',', '"', '\r', '\n' }) < 0) return s;
            return "\"" + s.Replace("\"", "\"\"") + "\"";
        }

        // CSV 인젝션 방어: 스프레드시트가 수식으로 해석하는 선행 문자를 작은따옴표로 막는다.
        // 숫자(음수 "-12" 등)는 수식이 아니므로 그대로 둔다.
        public static string GuardFormula(string value)
        {
            if (value.Length == 0) return value;
            char c = value[0];
            if (c is '=' or '+' or '@' or '\t' or '\r') return "'" + value;
            if (c == '-' && !(value.Length > 1 && char.IsDigit(value[1]))) return "'" + value;
            return value;
        }

        // 따옴표 안의 개행까지 처리하기 위해 줄 단위가 아니라 텍스트 전체를 파싱한다.
        public static List<string[]> Parse(string text)
        {
            var rows = new List<string[]>();
            var row = new List<string>();
            var field = new StringBuilder();
            bool inQuotes = false;
            bool fieldStarted = false; // 빈 줄과 "빈 필드 하나"를 구분하기 위해 사용

            for (int i = 0; i < text.Length; i++)
            {
                char c = text[i];

                if (inQuotes)
                {
                    if (c == '"')
                    {
                        if (i + 1 < text.Length && text[i + 1] == '"') { field.Append('"'); i++; }
                        else inQuotes = false;
                    }
                    else field.Append(c);
                    continue;
                }

                switch (c)
                {
                    case '"':
                        inQuotes = true;
                        fieldStarted = true;
                        break;
                    case ',':
                        row.Add(field.ToString());
                        field.Clear();
                        fieldStarted = true;
                        break;
                    case '\r':
                        if (i + 1 < text.Length && text[i + 1] == '\n') i++;
                        EndRow();
                        break;
                    case '\n':
                        EndRow();
                        break;
                    default:
                        field.Append(c);
                        fieldStarted = true;
                        break;
                }
            }

            if (fieldStarted || field.Length > 0 || row.Count > 0) EndRow();
            return rows;

            void EndRow()
            {
                if (!fieldStarted && field.Length == 0 && row.Count == 0) return; // 완전히 빈 줄은 건너뛴다
                row.Add(field.ToString());
                rows.Add(row.ToArray());
                row.Clear();
                field.Clear();
                fieldStarted = false;
            }
        }

        // 수식 방어용으로 붙였던 작은따옴표를 읽을 때 되돌린다(원래 값이 '로 시작했을 가능성은 무시한다).
        public static string Unguard(string value)
        {
            if (value.Length >= 2 && value[0] == '\'' && (value[1] is '=' or '+' or '@' or '\t' or '\r' or '-'))
                return value.Substring(1);
            return value;
        }
    }
}
