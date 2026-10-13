using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Net.Mail;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace KetworkScanner.Notifications
{
    // 변화 감지 결과를 외부 채널(웹훅/syslog/메일)로 보낸다. 채널 하나가 실패해도 나머지는 계속 보낸다.
    public interface INotificationChannel
    {
        string Name { get; }
        Task SendAsync(string subject, string body, CancellationToken ct);
    }

    public sealed class Notifier
    {
        private readonly NotificationSettings _settings;
        private readonly IReadOnlyList<INotificationChannel> _channels;

        public Notifier(NotificationSettings settings, IEnumerable<INotificationChannel>? channels = null)
        {
            _settings = settings;
            _channels = (channels ?? BuildChannels(settings)).ToList();
        }

        public static IEnumerable<INotificationChannel> BuildChannels(NotificationSettings s)
        {
            if (!string.IsNullOrWhiteSpace(s.WebhookUrl)) yield return new WebhookChannel(s.WebhookUrl);
            if (!string.IsNullOrWhiteSpace(s.SyslogHost)) yield return new SyslogChannel(s.SyslogHost, s.SyslogPort);
            if (!string.IsNullOrWhiteSpace(s.SmtpHost) && !string.IsNullOrWhiteSpace(s.MailTo)) yield return new SmtpChannel(s);
        }

        // 스캔 변화 목록을 받아 설정(보안 관련만/전부)에 따라 걸러 보낸다. 보낸 채널 수를 돌려준다.
        public async Task<int> NotifyChangesAsync(string systemName, IReadOnlyList<ScanChange> changes, CancellationToken ct)
        {
            if (!_settings.Enabled || _channels.Count == 0) return 0;

            List<ScanChange> selected = _settings.OnSecurityOnly
                ? changes.Where(c => ScanDiff.IsSecurityRelevant(c.Type)).ToList()
                : changes.ToList();
            if (selected.Count == 0) return 0;

            int security = selected.Count(c => ScanDiff.IsSecurityRelevant(c.Type));
            string subject = $"[KetworkScanner] {systemName}: {selected.Count} {Localization.T("change.detected")}"
                             + (security > 0 ? $" ({security} {Localization.T("change.securityalert")})" : "");
            var body = new StringBuilder();
            body.AppendLine(subject);
            body.AppendLine(DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture));
            foreach (ScanChange c in selected) body.AppendLine("- " + ScanDiff.Describe(c));

            return await SendAllAsync(subject, body.ToString(), ct).ConfigureAwait(false);
        }

        public async Task<int> SendAllAsync(string subject, string body, CancellationToken ct)
        {
            int sent = 0;
            foreach (INotificationChannel ch in _channels)
            {
                try
                {
                    await ch.SendAsync(subject, body, ct).ConfigureAwait(false);
                    sent++;
                }
                catch (Exception ex)
                {
                    AppLogger.LogError("Notifier", $"{ch.Name}: {ex.Message}");
                }
            }
            return sent;
        }
    }

    // Slack/Teams/Discord/Mattermost 등 대부분의 incoming webhook이 받아들이는 {"text": ...} 형식.
    public sealed class WebhookChannel : INotificationChannel
    {
        private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(20) };
        private readonly string _url;

        public WebhookChannel(string url) { _url = url; }
        public string Name => "webhook";

        public async Task SendAsync(string subject, string body, CancellationToken ct)
        {
            string json = JsonSerializer.Serialize(new { text = body, title = subject, content = body });
            using var content = new StringContent(json, Encoding.UTF8, "application/json");
            using HttpResponseMessage resp = await Http.PostAsync(_url, content, ct).ConfigureAwait(false);
            resp.EnsureSuccessStatusCode();
        }
    }

    // RFC 5424 UDP syslog. facility local0(16), 보안 관련은 warning(4), 그 외 notice(5).
    public sealed class SyslogChannel : INotificationChannel
    {
        private readonly string _host;
        private readonly int _port;

        public SyslogChannel(string host, int port) { _host = host; _port = port; }
        public string Name => "syslog";

        public async Task SendAsync(string subject, string body, CancellationToken ct)
        {
            using var udp = new UdpClient();
            string host = Environment.MachineName;
            foreach (string line in body.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                int severity = line.Contains('⚠') ? 4 : 5;
                int pri = 16 * 8 + severity;
                string msg = $"<{pri}>1 {DateTime.UtcNow:yyyy-MM-ddTHH:mm:ss.fffZ} {host} KetworkScanner - - - {line.Trim()}";
                byte[] bytes = Encoding.UTF8.GetBytes(msg);
                await udp.SendAsync(bytes, bytes.Length, _host, _port).ConfigureAwait(false);
                ct.ThrowIfCancellationRequested();
            }
        }
    }

    public sealed class SmtpChannel : INotificationChannel
    {
        private readonly NotificationSettings _s;
        public SmtpChannel(NotificationSettings s) { _s = s; }
        public string Name => "smtp";

        public async Task SendAsync(string subject, string body, CancellationToken ct)
        {
            using var client = new SmtpClient(_s.SmtpHost, _s.SmtpPort)
            {
                EnableSsl = _s.SmtpUseStartTls,
                Timeout = 20000,
            };
            if (!string.IsNullOrEmpty(_s.SmtpUser))
                client.Credentials = new System.Net.NetworkCredential(_s.SmtpUser, _s.SmtpPassword);

            using var mail = new MailMessage
            {
                From = new MailAddress(string.IsNullOrWhiteSpace(_s.MailFrom) ? _s.SmtpUser : _s.MailFrom),
                Subject = subject,
                Body = body,
                BodyEncoding = Encoding.UTF8,
                SubjectEncoding = Encoding.UTF8,
            };
            foreach (string to in _s.MailTo.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries))
                mail.To.Add(to.Trim());

            await client.SendMailAsync(mail, ct).ConfigureAwait(false);
        }
    }
}
