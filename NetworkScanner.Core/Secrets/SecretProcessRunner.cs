using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading.Tasks;

namespace NetworkScanner.Secrets
{
    // OS 자격 증명 도구(security, secret-tool)를 실행하는 공통 헬퍼.
    // 표준입력으로 비밀을 전달할 수 있고(인자 노출 방지), 제한 시간 초과 시 프로세스를 강제 종료한다.
    internal static class SecretProcessRunner
    {
        public const int TimeoutMs = 5000;

        public sealed class Result
        {
            public bool Started { get; init; }
            public bool TimedOut { get; init; }
            public int ExitCode { get; init; } = -1;
            public string StdOut { get; init; } = "";
            public string StdErr { get; init; } = "";

            public bool Succeeded => Started && !TimedOut && ExitCode == 0;
        }

        public static Result Run(string fileName, IReadOnlyList<string> arguments, string? stdin = null)
        {
            try
            {
                var psi = new ProcessStartInfo(fileName)
                {
                    RedirectStandardInput = stdin != null,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                };
                foreach (string arg in arguments) psi.ArgumentList.Add(arg);

                using Process? process = Process.Start(psi);
                if (process == null) return new Result { Started = false };

                // 출력 파이프가 가득 차서 자식이 멈추지 않도록 먼저 비동기로 읽기 시작한다.
                Task<string> stdoutTask = process.StandardOutput.ReadToEndAsync();
                Task<string> stderrTask = process.StandardError.ReadToEndAsync();

                if (stdin != null)
                {
                    try
                    {
                        process.StandardInput.Write(stdin);
                        process.StandardInput.Close();
                    }
                    catch
                    {
                        // 자식이 입력을 읽기 전에 종료한 경우 — 종료 코드로 판단한다.
                    }
                }

                if (!process.WaitForExit(TimeoutMs))
                {
                    try { process.Kill(entireProcessTree: true); } catch { }
                    try { process.WaitForExit(); } catch { }
                    return new Result { Started = true, TimedOut = true };
                }

                // 리다이렉트된 스트림이 모두 비워질 때까지 대기(비동기 읽기 완료 보장).
                process.WaitForExit();

                return new Result
                {
                    Started = true,
                    ExitCode = process.ExitCode,
                    StdOut = stdoutTask.GetAwaiter().GetResult(),
                    StdErr = stderrTask.GetAwaiter().GetResult(),
                };
            }
            catch
            {
                // 도구가 설치되어 있지 않은 경우(Win32Exception) 등.
                return new Result { Started = false };
            }
        }

        // 도구가 실행 가능한지만 확인한다(종료 코드는 무시 — 인자 없이 실행하면 사용법만 출력하는 도구가 많다).
        public static bool CanStart(string fileName, params string[] arguments)
        {
            Result result = Run(fileName, arguments);
            return result.Started && !result.TimedOut;
        }

        // 도구 출력의 마지막 줄바꿈만 제거한다(비밀 값 자체의 공백은 보존).
        public static string TrimTrailingNewline(string value)
        {
            if (value.EndsWith("\r\n", StringComparison.Ordinal)) return value[..^2];
            if (value.EndsWith('\n') || value.EndsWith('\r')) return value[..^1];
            return value;
        }
    }
}
