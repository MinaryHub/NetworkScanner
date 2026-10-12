using System;
using System.Diagnostics;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace NetworkScanner.Network
{
    // 수신 TTL 측정. .NET의 PingReply.Options.Ttl은 macOS/Linux에서 "보낸" 옵션(128)을 돌려줘 OS 추정에 쓸 수 없으므로,
    // Unix에서는 시스템 ping 한 번의 출력("ttl=64")을 읽는다. Windows는 PingReply의 값이 정확하므로 쓰지 않는다.
    // 살아있는 호스트에 대해서만, 2단계(부가 조회)에서 호출한다.
    public interface ITtlProber
    {
        Task<int> MeasureAsync(string ip, int timeoutMs, CancellationToken ct);
    }

    public sealed class PingUtilityTtlProber : ITtlProber
    {
        public Task<int> MeasureAsync(string ip, int timeoutMs, CancellationToken ct) => TtlProbe.MeasureAsync(ip, timeoutMs, ct);
    }

    public sealed class NullTtlProber : ITtlProber
    {
        public Task<int> MeasureAsync(string ip, int timeoutMs, CancellationToken ct) => Task.FromResult(0);
    }

    public static class TtlProbe
    {
        private static readonly Regex TtlRegex = new(@"\bttl[=:]\s*(\d+)", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        public static bool IsNeeded => !OperatingSystem.IsWindows();

        public static async Task<int> MeasureAsync(string ip, int timeoutMs, CancellationToken ct)
        {
            if (!IsNeeded) return 0;
            try
            {
                var psi = new ProcessStartInfo("ping")
                {
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                };
                psi.ArgumentList.Add("-c"); psi.ArgumentList.Add("1");
                psi.ArgumentList.Add("-n");
                if (OperatingSystem.IsMacOS())
                {
                    psi.ArgumentList.Add("-W"); psi.ArgumentList.Add(Math.Max(100, timeoutMs).ToString());   // ms
                }
                else
                {
                    psi.ArgumentList.Add("-W"); psi.ArgumentList.Add(Math.Max(1, (timeoutMs + 999) / 1000).ToString()); // s
                }
                psi.ArgumentList.Add(ip);

                using Process? p = Process.Start(psi);
                if (p == null) return 0;
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(timeoutMs + 1500);
                Task<string> output = p.StandardOutput.ReadToEndAsync(cts.Token);
                try { await p.WaitForExitAsync(cts.Token).ConfigureAwait(false); }
                catch (OperationCanceledException) { try { p.Kill(); } catch { } return 0; }
                Match m = TtlRegex.Match(await output.ConfigureAwait(false));
                return m.Success && int.TryParse(m.Groups[1].Value, out int ttl) ? ttl : 0;
            }
            catch
            {
                return 0;
            }
        }
    }
}
