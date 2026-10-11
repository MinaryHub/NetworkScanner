using System;
using System.Runtime.Versioning;

namespace NetworkScanner.Secrets
{
    // Linux 전용. libsecret의 `secret-tool`로 Secret Service(GNOME Keyring, KWallet 브리지 등)에 저장한다.
    // 속성은 service=NetworkScanner, account=<key>로, 이전 버전 CredentialProtector가 만든 항목("ftp-password")과 호환된다.
    // 비밀은 표준입력으로 전달되므로 명령 인자에 노출되지 않는다.
    [SupportedOSPlatform("linux")]
    public sealed class LinuxSecretToolSecretStore : ISecretStore
    {
        public const string ServiceName = "NetworkScanner";

        private const string Tool = "secret-tool";

        public string Name => "libsecret";

        // 인자 없이 실행하면 사용법만 출력하고 비정상 종료하지만, 프로세스가 뜨기만 하면 설치된 것으로 본다.
        public bool IsAvailable()
            => OperatingSystem.IsLinux() && SecretProcessRunner.CanStart(Tool);

        public bool TrySet(string key, string secret)
        {
            SecretKey.Validate(key);
            if (secret == null) throw new ArgumentNullException(nameof(secret));
            if (!OperatingSystem.IsLinux()) return false;

            var result = SecretProcessRunner.Run(Tool,
                new[] { "store", "--label=NetworkScanner " + key, "service", ServiceName, "account", key },
                stdin: secret);

            if (result.Succeeded) return true;

            SecretStoreDiagnostics.Report(Name, "'" + key + "' 저장 실패: " + Describe(result));
            return false;
        }

        public string? Get(string key)
        {
            SecretKey.Validate(key);
            if (!OperatingSystem.IsLinux()) return null;

            var result = SecretProcessRunner.Run(Tool,
                new[] { "lookup", "service", ServiceName, "account", key });

            if (result.Succeeded)
            {
                // 항목이 없으면 secret-tool은 아무 출력 없이 1로 종료하지만, 일부 버전은 0으로 종료하므로 빈 출력도 없음으로 본다.
                return result.StdOut.Length == 0 ? null : SecretProcessRunner.TrimTrailingNewline(result.StdOut);
            }

            // exit 1 = 항목 없음(정상). 그 외는 데몬 접근 실패 등.
            if (result.Started && !result.TimedOut && result.ExitCode == 1) return null;

            SecretStoreDiagnostics.Report(Name, "'" + key + "' 읽기 실패: " + Describe(result));
            return null;
        }

        public void Remove(string key)
        {
            SecretKey.Validate(key);
            if (!OperatingSystem.IsLinux()) return;

            var result = SecretProcessRunner.Run(Tool,
                new[] { "clear", "service", ServiceName, "account", key });

            // 항목이 없어도 secret-tool clear는 0으로 종료한다.
            if (result.Succeeded) return;

            SecretStoreDiagnostics.Report(Name, "'" + key + "' 삭제 실패: " + Describe(result));
        }

        private static string Describe(SecretProcessRunner.Result result)
        {
            if (!result.Started) return "'secret-tool' 도구를 실행할 수 없습니다(libsecret-tools 패키지 필요).";
            if (result.TimedOut) return "'secret-tool' 응답 시간 초과(" + SecretProcessRunner.TimeoutMs + "ms).";
            string err = SecretProcessRunner.TrimTrailingNewline(result.StdErr);
            return "exit " + result.ExitCode + (err.Length > 0 ? " - " + err : "");
        }
    }
}
