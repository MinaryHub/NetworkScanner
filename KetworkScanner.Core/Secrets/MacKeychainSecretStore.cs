using System;
using System.Runtime.Versioning;
using System.Text;

namespace KetworkScanner.Secrets
{
    // macOS 전용. 로그인 Keychain의 generic password 항목(service "KetworkScanner", account = 키 이름)에 저장한다.
    // 비밀은 명령 인자로 넘기지 않는다: `security -i`(대화형 모드)를 띄우고 표준입력으로
    // add-generic-password 명령을 써 넣으므로 다른 프로세스가 ps 등으로 비밀을 볼 수 없다.
    // 계정 이름 규칙(account = key)은 이전 버전 CredentialProtector가 만든 항목("ftp-password")과 호환된다.
    [SupportedOSPlatform("macos")]
    public sealed class MacKeychainSecretStore : ISecretStore
    {
        public const string ServiceName = "KetworkScanner";
        // 이름 변경(NetworkScanner → KetworkScanner) 전에 저장된 항목도 읽는다.
        public const string LegacyServiceName = "NetworkScanner";

        private const string Tool = "security";
        private const int NotFoundExitCode = 44; // errSecItemNotFound

        public string Name => "keychain";

        public bool IsAvailable()
            => OperatingSystem.IsMacOS() && SecretProcessRunner.CanStart(Tool, "help");

        public bool TrySet(string key, string secret)
        {
            SecretKey.Validate(key);
            if (secret == null) throw new ArgumentNullException(nameof(secret));
            if (!OperatingSystem.IsMacOS()) return false;

            // 대화형 모드는 한 줄이 한 명령이므로 줄바꿈이 들어간 비밀은 표현할 수 없다.
            if (secret.IndexOf('\n') >= 0 || secret.IndexOf('\r') >= 0)
            {
                SecretStoreDiagnostics.Report(Name, "'" + key + "': 줄바꿈이 포함된 비밀은 Keychain에 저장할 수 없습니다.");
                return false;
            }

            string command = "add-generic-password -a \"" + Quote(key) + "\" -s \"" + ServiceName
                             + "\" -w \"" + Quote(secret) + "\" -U\n";

            var result = SecretProcessRunner.Run(Tool, new[] { "-i" }, stdin: command);
            if (result.Succeeded) return true;

            SecretStoreDiagnostics.Report(Name, "'" + key + "' 저장 실패: " + Describe(result));
            return false;
        }

        // 새 서비스 이름에 없으면 이름 변경 전 항목(NetworkScanner)을 읽는다.
        public string? Get(string key) => Get(key, ServiceName) ?? Get(key, LegacyServiceName);

        private string? Get(string key, string service)
        {
            SecretKey.Validate(key);
            if (!OperatingSystem.IsMacOS()) return null;

            // -w는 비밀에 비ASCII/특수 문자가 있으면 16진수 문자열을 출력해 평문 16진수 비밀과 구분할 수 없다.
            // -g는 stderr에 `password: "평문"` 또는 `password: 0x<HEX>  "..."` 형식으로 출력하므로 모호하지 않다.
            var result = SecretProcessRunner.Run(Tool,
                new[] { "find-generic-password", "-a", key, "-s", service, "-g" });

            if (result.Succeeded)
            {
                string? parsed = ParsePasswordLine(result.StdErr) ?? ParsePasswordLine(result.StdOut);
                if (parsed == null)
                {
                    SecretStoreDiagnostics.Report(Name, "'" + key + "' 읽기 실패: security 출력 형식을 해석할 수 없습니다.");
                }
                return parsed;
            }
            if (result.Started && !result.TimedOut && result.ExitCode == NotFoundExitCode) return null;

            SecretStoreDiagnostics.Report(Name, "'" + key + "' 읽기 실패: " + Describe(result));
            return null;
        }

        private const string PasswordLinePrefix = "password: ";

        // `password: ` 줄을 찾아 비밀을 복원한다. 형식을 알 수 없으면 null.
        private static string? ParsePasswordLine(string output)
        {
            foreach (string rawLine in output.Split('\n'))
            {
                string line = rawLine.TrimEnd('\r');
                if (!line.StartsWith(PasswordLinePrefix, StringComparison.Ordinal)) continue;

                string rest = line.Substring(PasswordLinePrefix.Length);
                if (rest.Length == 0) return "";

                if (rest.StartsWith("0x", StringComparison.Ordinal))
                {
                    int end = 2;
                    while (end < rest.Length && Uri.IsHexDigit(rest[end])) end++;
                    try
                    {
                        return Encoding.UTF8.GetString(Convert.FromHexString(rest.AsSpan(2, end - 2)));
                    }
                    catch (FormatException)
                    {
                        return null;
                    }
                }

                if (rest.Length >= 2 && rest[0] == '"' && rest[^1] == '"')
                {
                    return rest.Substring(1, rest.Length - 2);
                }
                return null;
            }
            return null;
        }

        public void Remove(string key)
        {
            SecretKey.Validate(key);
            if (!OperatingSystem.IsMacOS()) return;

            var result = SecretProcessRunner.Run(Tool,
                new[] { "delete-generic-password", "-a", key, "-s", ServiceName });

            if (result.Succeeded) return;
            if (result.Started && !result.TimedOut && result.ExitCode == NotFoundExitCode) return;

            SecretStoreDiagnostics.Report(Name, "'" + key + "' 삭제 실패: " + Describe(result));
        }

        // security 대화형 파서의 큰따옴표 문자열 규칙: 백슬래시와 큰따옴표만 이스케이프하면 된다.
        private static string Quote(string value)
        {
            var sb = new StringBuilder(value.Length + 8);
            foreach (char c in value)
            {
                if (c == '\\' || c == '"') sb.Append('\\');
                sb.Append(c);
            }
            return sb.ToString();
        }

        private static string Describe(SecretProcessRunner.Result result)
        {
            if (!result.Started) return "'security' 도구를 실행할 수 없습니다.";
            if (result.TimedOut) return "'security' 응답 시간 초과(" + SecretProcessRunner.TimeoutMs + "ms).";
            string err = SecretProcessRunner.TrimTrailingNewline(result.StdErr);
            return "exit " + result.ExitCode + (err.Length > 0 ? " - " + err : "");
        }
    }
}
