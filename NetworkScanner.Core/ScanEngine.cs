using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using NetworkScanner.History;
using NetworkScanner.Network;
using NetworkScanner.Upload;

namespace NetworkScanner
{
    // 스캔/저장/불러오기 로직을 UI 프레임워크에 의존하지 않는 형태로 모아 둔 것.
    // GUI/CLI/서비스가 이 클래스를 공유하며, 진행 상태/메시지/오류는 이벤트로 알린다.
    // 네트워크·ARP·DNS·업로드·이력은 ScanServices의 인터페이스를 통해서만 접근한다(테스트에서는 가짜로 교체).
    public class ScanEngine
    {
        private readonly IPInfoList _items;
        private readonly OUIInfo _oui;
        private readonly ScanServices _services;
        private readonly object _scanLock = new();
        // 병렬 스캔 중 결과 목록 쓰기를 직렬화한다. UI는 이 락을 잡고 스냅샷을 만든다.
        private readonly object _itemsLock = new();
        private CancellationTokenSource? _scanCts;
        private Dictionary<string, AnnotationStore.Annotation> _annotations = new();
        private List<int> _userPorts = new();

        public IScanConfigProvider Config { get; set; }
        public ScanOptions Options { get; set; } = new();
        public Task? Scanning { get; private set; }
        public IPInfoList Items => _items;
        public ScanServices Services => _services;

        // Avalonia는 스냅샷 생성 시, CLI는 결과 출력 시 이 lock을 사용한다.
        public object ItemsSyncRoot => _itemsLock;

        public event Action<string>? Message;
        public event Action<int>? ProgressMaxChanged;
        public event Action<int>? ProgressChanged;
        public event Action<int, int, int>? ResultsSummaryChanged; // alive, dead, total
        public event Action? ItemsRefreshNeeded;
        public event Action? ScanStarted;
        public event Action? ScanFinished;
        // 대역 스캔이 끝난 뒤 직전 스캔과 비교한 변화 목록(비어 있으면 발생하지 않음).
        public event Action<IReadOnlyList<ScanChange>>? ScanChangesDetected;

        public ScanEngine(IPInfoList items, OUIInfo oui, IScanConfigProvider config, ScanServices? services = null, ScanOptions? options = null)
        {
            _items = items;
            _oui = oui;
            Config = config;
            _services = services ?? new ScanServices();
            if (options != null) Options = options;
        }

        public void InitFromConfig()
        {
            _userPorts = ProbeExtensions.ParsePorts(Config.GetPortList());
        }

        // ---------------------------------------------------------------- CSV 저장/불러오기

        private static readonly string[] CsvHeader =
        {
            "IPAddress", "Port", "SystemName", "Description", "Commitdate", "Alive", "MacAddress", "Vendor", "RoundTime",
            "Service", "Ttl", "HasProhibitedPort",
        };

        public void LoadIPInfo(string filename)
        {
            try
            {
                string text = File.ReadAllText(filename, Encoding.UTF8);
                List<IPInfo> parsed = ParseCsv(text);
                lock (_itemsLock)
                {
                    _items.Clear();
                    foreach (IPInfo ip in parsed) _items.Add(ip);
                }
                RaiseResultsSummary();
                ItemsRefreshNeeded?.Invoke();
            }
            catch (Exception ex)
            {
                Message?.Invoke(string.Format(Localization.T("msg.file.loadfailed"), ex.Message));
            }
        }

        // 헤더 이름으로 열을 찾으므로 열 순서/개수가 다른 구버전 파일도 읽을 수 있다.
        internal static List<IPInfo> ParseCsv(string text)
        {
            var result = new List<IPInfo>();
            List<string[]> rows = CsvCodec.Parse(text);
            if (rows.Count == 0) return result;

            var index = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < rows[0].Length; i++) index[rows[0][i].Trim()] = i;
            if (!index.ContainsKey("IPAddress")) return result;

            string Get(string[] row, string col)
                => index.TryGetValue(col, out int i) && i < row.Length ? CsvCodec.Unguard(row[i]) : "";

            for (int r = 1; r < rows.Count; r++)
            {
                string[] row = rows[r];
                try
                {
                    string ip = Get(row, "IPAddress");
                    if (string.IsNullOrWhiteSpace(ip)) continue;
                    var info = new IPInfo
                    {
                        Ip = ip,
                        Ports = Get(row, "Port"),
                        SystemName = Get(row, "SystemName"),
                        Description = Get(row, "Description"),
                        CommitDate = Get(row, "Commitdate"),
                        Macaddr = Get(row, "MacAddress"),
                        Vendor = Get(row, "Vendor"),
                        RountTime = Get(row, "RoundTime"),
                        Service = Get(row, "Service"),
                    };
                    if (bool.TryParse(Get(row, "Alive"), out bool alive)) info.Alive = alive;
                    if (int.TryParse(Get(row, "Ttl"), NumberStyles.Integer, CultureInfo.InvariantCulture, out int ttl)) info.Ttl = ttl;
                    if (bool.TryParse(Get(row, "HasProhibitedPort"), out bool hp)) info.HasProhibitedPort = hp;
                    result.Add(info);
                }
                catch (Exception ex)
                {
                    AppLogger.LogError("NetworkScanner", string.Format(Localization.T("msg.parse.skipped"), "csv", ex.Message));
                }
            }
            return result;
        }

        internal static string BuildCsv(IEnumerable<IPInfo> items)
        {
            var sb = new StringBuilder();
            sb.Append(CsvCodec.FormatLine(CsvHeader)).Append("\r\n");
            foreach (IPInfo i in items)
            {
                sb.Append(CsvCodec.FormatLine(new[]
                {
                    i.Ip, i.Ports, i.SystemName, i.Description, i.CommitDate,
                    i.Alive.ToString(), i.Macaddr, i.Vendor, i.RountTime,
                    i.Service, i.Ttl.ToString(CultureInfo.InvariantCulture), i.HasProhibitedPort.ToString(),
                })).Append("\r\n");
            }
            return sb.ToString();
        }

        public static string SanitizeFileNameComponent(string name)
        {
            if (string.IsNullOrEmpty(name)) return "";

            string result = name.Replace("..", "");
            foreach (char c in Path.GetInvalidFileNameChars())
            {
                result = result.Replace(c, '_');
            }
            return result;
        }

        public static string GetEnvDirectory() => UserDataPaths.Resolve("env");

        public async Task WriteIPInfo(bool autosave, string systemName)
        {
            List<IPInfo> snapshot;
            lock (_itemsLock) snapshot = new List<IPInfo>(_items);
            if (snapshot.Count == 0)
            {
                Message?.Invoke(Localization.T("msg.file.nothingtosave"));
                return;
            }

            try
            {
                string path = GetEnvDirectory();
                Directory.CreateDirectory(path);

                string autosaveTag = autosave ? "_(SCHEDULING)" : "";
                string filename = $"{SanitizeFileNameComponent(systemName)}{_services.Clock():_yyyyMMdd_HHmmss}{autosaveTag}.csv";
                string full = Path.Combine(path, filename);
                await File.WriteAllTextAsync(full, BuildCsv(snapshot), new UTF8Encoding(false)).ConfigureAwait(false);

                // 사용자가 지정한 이름/비고를 IP 기준으로 보관해 다음 스캔/재시작 후에도 유지되게 한다.
                AnnotationStore.Save(snapshot);

                Message?.Invoke(string.Format(Localization.T("msg.file.saved"), filename));
                await UploadAsync(full).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                AppLogger.LogError("NetworkScanner", "IP list save failed", ex);
                Message?.Invoke(string.Format(Localization.T("msg.file.savefailed"), ex.Message));
            }
        }

        private async Task UploadAsync(string localPath)
        {
            if (_services.Uploader == null) return;
            UploadSettings settings = Config.GetUploadSettings();
            if (!settings.Enabled) return;
            try
            {
                await _services.Uploader.UploadAsync(localPath, settings, m => Message?.Invoke(m), CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                AppLogger.LogError("NetworkScanner", "upload failed", ex);
            }
        }

        // 시스템 이름으로 시작하는 가장 최근 CSV를 불러온다. 대소문자를 구분하는 파일시스템에서도 찾도록 무시 비교한다.
        public void GetLatestFilePath(string prefixName)
        {
            if (string.IsNullOrEmpty(prefixName)) return;

            string path = GetEnvDirectory();
            if (!Directory.Exists(path)) return;

            string prefix = SanitizeFileNameComponent(prefixName);
            FileInfo? file = new DirectoryInfo(path)
                .EnumerateFiles("*.csv", new EnumerationOptions { MatchCasing = MatchCasing.CaseInsensitive })
                .Where(fi => fi.Name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(fi => fi.LastWriteTime)
                .FirstOrDefault();

            if (file != null) LoadIPInfo(file.FullName);
        }

        // ---------------------------------------------------------------- 스캔 시작/중지

        // 취소 여부 확인과 Scanning 필드 대입을 한 lock 안에서 처리해 두 스캔이 동시에 시작되는 경쟁 상태를 막는다.
        private bool TryBeginScan(out CancellationToken token)
        {
            lock (_scanLock)
            {
                if (IsScanning())
                {
                    Message?.Invoke(Localization.T("scan.alreadyscanning"));
                    token = default;
                    return false;
                }

                _scanCts?.Dispose();
                _scanCts = new CancellationTokenSource();
                token = _scanCts.Token;
                return true;
            }
        }

        public void ScanningStop()
        {
            lock (_scanLock)
            {
                _scanCts?.Cancel();
            }
            Message?.Invoke(Localization.T("scan.cancelrequested"));
        }

        public bool IsScanning()
        {
            Task? t = Scanning;
            return t != null && !t.IsCompleted;
        }

        public bool StartSchedulingScan(string systemName)
        {
            if (!TryBeginScan(out CancellationToken token)) return false;
            Scanning = RunTracked(DoScanAllRange(true, systemName, token));
            return true;
        }

        public bool StartRefreshAllRange(string systemName)
        {
            if (!TryBeginScan(out CancellationToken token)) return false;
            Scanning = RunTracked(DoScanAllRange(false, systemName, token));
            return true;
        }

        public bool StartCheckUserPortList(string ip)
        {
            if (!TryBeginScan(out CancellationToken token)) return false;
            Scanning = RunTracked(DoCheckPortList(ip, ProbeExtensions.ParsePorts(Config.GetPortList()), "portcheck.start.user", token));
            return true;
        }

        public bool StartCheckReservedPortList(string ip)
        {
            if (!TryBeginScan(out CancellationToken token)) return false;
            Scanning = RunTracked(DoCheckPortList(ip, Config.GetReservedPortList().Select(p => p.PortNo).ToList(), "portcheck.start.reserved", token));
            return true;
        }

        public bool StartCheckProhibitPortList(string ip)
        {
            if (!TryBeginScan(out CancellationToken token)) return false;
            Scanning = RunTracked(DoCheckPortList(ip, Config.GetProhibitPortList().Select(p => p.PortNo).ToList(), "portcheck.start.prohibit", token));
            return true;
        }

        // Start* 메서드가 공통으로 거치는 래퍼: 스캔 시작/종료를 이벤트로 알리고, 예외는 로그와 메시지로 흘려보낸다.
        private async Task RunTracked(Task task)
        {
            ScanStarted?.Invoke();
            try
            {
                await task.ConfigureAwait(false);
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                AppLogger.LogError("NetworkScanner", "scan failed", ex);
                Message?.Invoke(ex.Message);
            }
            finally
            {
                ScanFinished?.Invoke();
            }
        }

        // ---------------------------------------------------------------- 단일 호스트 조작

        public async Task PingOnceAsync(string ip, CancellationToken ct = default)
        {
            if (!IPAddress.TryParse(ip, out IPAddress? addr)) return;

            PingResult? reply = await _services.Pinger.PingAsync(addr, Options.PingTimeoutMs, ct).ConfigureAwait(false);
            bool alive = reply is { Success: true };
            ApplyPingResult(alive, alive ? reply!.Value.RoundtripMs : null, alive ? reply!.Value.Ttl : 0, ip);
            RaiseResultsSummary();

            string status = reply.HasValue ? reply.Value.Status : Localization.T("ping.failed");
            Message?.Invoke(string.Format(Localization.T("ping.manual"), ip, status));
        }

        public void PingOnce(string ip) => _ = PingOnceAsync(ip);

        private async Task DoCheckPortList(string ip, List<int> ports, string startKey, CancellationToken token)
        {
            IPInfo? ipInfo;
            lock (_itemsLock) ipInfo = _items.GetItem(ip);
            if (ipInfo == null)
            {
                Message?.Invoke(string.Format(Localization.T("portcheck.unknownhost"), ip));
                return;
            }

            int maxCnt = ports.Count;
            ProgressMaxChanged?.Invoke(maxCnt);
            Message?.Invoke(string.Format(Localization.T(startKey), ip));

            int done = 0;
            var open = new ConcurrentBag<int>();
            var throttle = new MessageThrottle(this);
            try
            {
                using var gate = new SemaphoreSlim(Options.PortParallelism);
                var tasks = ports.Select(async port =>
                {
                    await gate.WaitAsync(token).ConfigureAwait(false);
                    try
                    {
                        if (await _services.Ports.IsOpenAsync(ip, port, Options.PortTimeoutMs, token).ConfigureAwait(false))
                            open.Add(port);
                    }
                    finally { gate.Release(); }

                    int cur = Interlocked.Increment(ref done);
                    ProgressChanged?.Invoke(cur);
                    throttle.Progress(cur, maxCnt, () => string.Format(Localization.T("portcheck.progress"), cur, maxCnt, ip, port));
                });
                await Task.WhenAll(tasks).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { }

            string openPorts = ProbeExtensions.FormatPorts(open.OrderBy(p => p));
            HashSet<int> prohibited = GetProhibitedPortSet();
            lock (_itemsLock)
            {
                ipInfo.Ports = openPorts;
                ipInfo.HasProhibitedPort = ContainsProhibitedPort(openPorts, prohibited);
            }
            ItemsRefreshNeeded?.Invoke();
            ProgressChanged?.Invoke(0);
            Message?.Invoke(string.Format(Localization.T("portcheck.done"), ip, openPorts));
        }

        // ---------------------------------------------------------------- 대역 스캔

        // 스캔을 2단계로 나눈다.
        //  1단계: 대역 전체를 병렬 Ping(+TCP 생존 확인)으로 훑어 살아있는 호스트를 빠르게 찾아 목록에 표시한다.
        //  2단계: 살아있는 호스트에 대해서만 느린 부가 정보(MAC/제조사/호스트명/열린 포트/배너)를 조회해 행을 채운다.
        public async Task DoScanAllRange(bool scheduling, string systemName, CancellationToken token)
        {
            DateTime started = _services.Clock();
            ScanRangeList ranges = Config.GetScanRanges();
            List<string> targets = BuildTargetIPList(ranges);
            int maxCnt = targets.Count;

            if (maxCnt == 0)
            {
                ProgressMaxChanged?.Invoke(0);
                Message?.Invoke(Localization.T("scan.norange"));
                return;
            }
            if (maxCnt > Options.MaxTargets)
            {
                ProgressMaxChanged?.Invoke(0);
                Message?.Invoke(string.Format(Localization.T("scan.toomanytargets"), maxCnt, Options.MaxTargets));
                return;
            }
            ProgressMaxChanged?.Invoke(maxCnt);

            // 스캔 중에는 설정을 다시 읽지 않는다(UI 스레드 마샬링을 피하고 일관된 설정으로 끝까지 돈다).
            bool usePortChecking = Config.GetUsePortChecking() == true;
            HashSet<int> prohibitedPorts = GetProhibitedPortSet();
            List<int> userPorts = _userPorts.Count > 0 ? _userPorts : ProbeExtensions.ParsePorts(Config.GetPortList());
            var options = new ParallelOptions { MaxDegreeOfParallelism = Options.Parallelism, CancellationToken = token };

            // 사용자가 지정해 둔 이름/비고를 읽어와, 스캔 중 새로 발견되는 호스트에 자동 병합한다.
            _annotations = AnnotationStore.Load();

            // 변화 감지 기준선: 현재 목록이 비어 있으면(재시작 직후) 이력 DB의 마지막 스캔을 쓴다.
            Dictionary<string, HostState> baseline = SnapshotStates();
            if (baseline.Count == 0 && _services.History != null)
            {
                try
                {
                    var last = _services.History.GetLastScanStates();
                    if (last != null) baseline = new Dictionary<string, HostState>(last);
                }
                catch (Exception ex) { AppLogger.LogWarn("NetworkScanner", "history baseline unavailable: " + ex.Message); }
            }

            // ---- 1단계: 빠른 Ping 스윕(+ ICMP 무응답 시 TCP로 생존 재확인) ----
            Message?.Invoke($"{Localization.T("scan.phase1.start")} ({maxCnt}). {started:yyyy/MM/dd HH:mm:ss}");
            var aliveIps = new ConcurrentBag<string>();
            int pinged = 0;
            var throttle = new MessageThrottle(this);
            try
            {
                await Parallel.ForEachAsync(targets, options, async (strIp, ct) =>
                {
                    PingResult? reply = await _services.Pinger.PingAsync(IPAddress.Parse(strIp), Options.PingTimeoutMs, ct).ConfigureAwait(false);
                    bool alive = reply is { Success: true };
                    long? roundtrip = alive ? reply!.Value.RoundtripMs : null;
                    int ttl = alive ? reply!.Value.Ttl : 0;

                    if (!alive)
                    {
                        alive = await _services.Ports.IsAliveByTcpAsync(strIp, Options.LivenessProbePorts, Options.TcpLivenessTimeoutMs, ct).ConfigureAwait(false);
                    }

                    if (alive) aliveIps.Add(strIp);
                    ApplyPingResult(alive, roundtrip, ttl, strIp);

                    int cur = Interlocked.Increment(ref pinged);
                    ProgressChanged?.Invoke(cur);
                    throttle.Progress(cur, maxCnt, () => $"{Localization.T("scan.phase1.progress")}: {strIp} ({cur}/{maxCnt})");
                    if (alive) RaiseResultsSummary();
                }).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { }
            RaiseResultsSummary();

            // ---- 2단계: 살아있는 호스트 부가 정보 조회 ----
            List<string> aliveList = aliveIps.OrderBy(ip => IPRangeUtil.ToUInt32(IPAddress.Parse(ip))).ToList();
            if (aliveList.Count > 0 && !token.IsCancellationRequested)
            {
                ProgressMaxChanged?.Invoke(aliveList.Count);
                Message?.Invoke($"{Localization.T("scan.phase2.start")} ({aliveList.Count})");
                int enriched = 0;
                try
                {
                    await Parallel.ForEachAsync(aliveList, options, async (strIp, ct) =>
                    {
                        await EnrichHostAsync(strIp, usePortChecking, userPorts, prohibitedPorts, ct).ConfigureAwait(false);

                        int cur = Interlocked.Increment(ref enriched);
                        ProgressChanged?.Invoke(cur);
                        throttle.Progress(cur, aliveList.Count, () => $"{Localization.T("scan.phase2.progress")}: {strIp} ({cur}/{aliveList.Count})");
                    }).ConfigureAwait(false);
                }
                catch (OperationCanceledException) { }
            }

            bool cancelled = token.IsCancellationRequested;
            DateTime finished = _services.Clock();

            // ---- 변화 감지: 기준선과 이번 결과를 비교해 신규/오프라인/MAC 변경/새 포트/위험 포트를 알린다. ----
            if (!cancelled)
            {
                List<ScanChange> changes = ScanDiff.ComputeChanges(baseline, SnapshotStates());
                if (changes.Count > 0) ScanChangesDetected?.Invoke(changes);
                RecordHistory(started, finished, systemName, scheduling);
            }

            ProgressChanged?.Invoke(0);
            Message?.Invoke(cancelled
                ? $"{Localization.T("scan.cancelled")} {finished:yyyy/MM/dd HH:mm:ss}"
                : $"{Localization.T("scan.completed")} {Localization.T("scan.alivecount")}: {aliveList.Count}. {finished:yyyy/MM/dd HH:mm:ss}");

            if (scheduling && !cancelled)
            {
                await WriteIPInfo(true, systemName).ConfigureAwait(false);
                await WriteAndUploadReport(systemName).ConfigureAwait(false); // 무인 스케줄 스캔은 HTML 리포트도 함께 남긴다.
            }
        }

        private void RecordHistory(DateTime started, DateTime finished, string systemName, bool scheduled)
        {
            if (_services.History == null) return;
            try
            {
                List<IPInfo> snapshot;
                lock (_itemsLock) snapshot = new List<IPInfo>(_items);
                _services.History.RecordScan(ScanRecord.FromItems(snapshot, started, finished, systemName, scheduled));
            }
            catch (Exception ex)
            {
                AppLogger.LogError("NetworkScanner", string.Format(Localization.T("msg.history.failed"), ex.Message));
            }
        }

        // HTML 리포트를 env 폴더에 저장하고, 업로드 설정이면 함께 업로드한다.
        private async Task WriteAndUploadReport(string systemName)
        {
            try
            {
                List<IPInfo> snapshot;
                lock (_itemsLock) snapshot = new List<IPInfo>(_items);
                if (snapshot.Count == 0) return;

                DateTime now = _services.Clock();
                string html = ReportGenerator.BuildHtml(snapshot, systemName, now.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture));
                string path = GetEnvDirectory();
                Directory.CreateDirectory(path);
                string filename = $"{SanitizeFileNameComponent(systemName)}{now:_yyyyMMdd_HHmmss}_report.html";
                string full = Path.Combine(path, filename);
                await File.WriteAllTextAsync(full, html, new UTF8Encoding(false)).ConfigureAwait(false);

                Message?.Invoke(string.Format(Localization.T("msg.report.saved"), filename));
                await UploadAsync(full).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                AppLogger.LogError("NetworkScanner", string.Format(Localization.T("msg.report.savefailed"), ex.Message));
            }
        }

        // 결과 목록의 현재 상태를 IP→상태 딕셔너리로 스냅샷한다(변화 감지 기준선/비교 대상으로 사용).
        private Dictionary<string, HostState> SnapshotStates()
        {
            lock (_itemsLock)
            {
                var map = new Dictionary<string, HostState>(_items.Count);
                foreach (IPInfo i in _items)
                {
                    map[i.Ip] = new HostState(i.Alive, i.Macaddr ?? "", i.Ports ?? "", i.HasProhibitedPort);
                }
                return map;
            }
        }

        // 스캔 대상 IP들을 미리 문자열 목록으로 펼친다. 잘못된 대역은 건너뛰며 안내 메시지를 남긴다.
        private List<string> BuildTargetIPList(ScanRangeList ranges)
        {
            var targets = new List<string>();
            foreach (ScanRangeInfo item in ranges)
            {
                if (!IPAddress.TryParse(item.StartIP, out IPAddress? s) || !IPAddress.TryParse(item.EndIP, out IPAddress? e)
                    || s.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork || e.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    Message?.Invoke(string.Format(Localization.T("scan.invalidrange"), item.StartIP, item.EndIP));
                    continue;
                }

                uint startVal = IPRangeUtil.ToUInt32(s);
                uint endVal = IPRangeUtil.ToUInt32(e);
                if (endVal < startVal) continue;

                for (uint ipVal = startVal; ipVal <= endVal; ipVal++)
                {
                    targets.Add(IPRangeUtil.FromUInt32(ipVal).ToString());
                    if (targets.Count > Options.MaxTargets) return targets; // 상한 초과는 호출자가 메시지로 처리
                }
            }
            return targets;
        }

        private HashSet<int> GetProhibitedPortSet()
        {
            List<RefPortInfo>? prohibitList = Config.GetProhibitPortList();
            if (prohibitList == null) return new HashSet<int>();
            return new HashSet<int>(prohibitList.Select(p => p.PortNo));
        }

        public static int ComputeIPCount(ScanRangeList ranges)
        {
            long cnt = 0;
            foreach (ScanRangeInfo info in ranges)
            {
                if (!IPAddress.TryParse(info.StartIP, out IPAddress? s) || !IPAddress.TryParse(info.EndIP, out IPAddress? e)) continue;
                if (s.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork || e.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) continue;
                uint startVal = IPRangeUtil.ToUInt32(s);
                uint endVal = IPRangeUtil.ToUInt32(e);
                if (endVal >= startVal) cnt += endVal - startVal + 1;
            }
            return (int)Math.Min(cnt, int.MaxValue);
        }

        // 1단계 전용: 생존 여부/응답시간/TTL만 반영한다.
        // roundtripMs가 null이면서 alive면 ICMP는 무응답이지만 TCP로 생존이 확인된 경우로, 응답시간을 "TCP"로 표기한다.
        private void ApplyPingResult(bool alive, long? roundtripMs, int ttl, string targetIp)
        {
            string roundTime = alive ? (roundtripMs.HasValue ? roundtripMs.Value.ToString(CultureInfo.InvariantCulture) : "TCP") : "Timeout";
            bool changed = false;

            lock (_itemsLock)
            {
                IPInfo? info = _items.GetItem(targetIp);
                if (info != null)
                {
                    info.RountTime = roundTime;
                    info.Alive = alive;
                    if (ttl > 0) info.Ttl = ttl;
                    changed = true;
                }
                else if (alive)
                {
                    var added = new IPInfo
                    {
                        Ip = targetIp,
                        Ports = "",
                        Description = "",
                        CommitDate = _services.Clock().ToString("yyyy/MM/dd HH:mm:ss", CultureInfo.InvariantCulture),
                        RountTime = roundTime,
                        Alive = true,
                        Macaddr = "",
                        Vendor = "",
                        SystemName = "",
                        Service = "",
                        Ttl = ttl,
                    };
                    // 사용자가 이전에 지정한 이름/비고가 있으면 새 호스트에 자동으로 채운다.
                    if (_annotations.TryGetValue(targetIp, out var note))
                    {
                        added.SystemName = note.Name;
                        added.Description = note.Description;
                    }
                    _items.Add(added);
                    changed = true;
                }
            }

            if (changed) ItemsRefreshNeeded?.Invoke();
        }

        // 2단계 전용: 살아있는 호스트 한 대의 MAC/제조사/호스트명/열린 포트/배너를 조회해 해당 행을 채운다.
        // 모든 조회는 결과 목록 락 밖에서 수행하고, 마지막에 짧게 락을 잡아 값만 반영한다.
        private async Task EnrichHostAsync(string targetIp, bool usePortChecking, List<int> userPorts, HashSet<int> prohibitedPorts, CancellationToken ct)
        {
            string? mac = _services.Arp.Resolve(targetIp);
            string vendor = string.IsNullOrEmpty(mac) ? "" : _oui.GetVender(mac);

            Task<string?> hostNameTask = _services.Dns.ReverseLookupAsync(targetIp, Options.DnsTimeoutMs, ct);
            List<int> open = usePortChecking
                ? await _services.Ports.OpenPortsAsync(targetIp, userPorts, Options.PortTimeoutMs, Options.PortParallelism, ct).ConfigureAwait(false)
                : new List<int>();
            string? hostName = await hostNameTask.ConfigureAwait(false);

            string openPorts = ProbeExtensions.FormatPorts(open);
            bool hasProhibited = open.Any(prohibitedPorts.Contains);
            string service = usePortChecking ? await GrabServiceAsync(targetIp, open, ct).ConfigureAwait(false) : "";

            bool changed = false;
            lock (_itemsLock)
            {
                IPInfo? info = _items.GetItem(targetIp);
                if (info != null)
                {
                    if (!string.IsNullOrEmpty(mac)) info.Macaddr = mac;
                    if (!string.IsNullOrEmpty(vendor)) info.Vendor = vendor;
                    if (string.IsNullOrEmpty(info.SystemName) && !string.IsNullOrEmpty(hostName) && hostName != targetIp)
                        info.SystemName = hostName;
                    if (usePortChecking)
                    {
                        info.Ports = openPorts;
                        info.HasProhibitedPort = hasProhibited;
                        if (!string.IsNullOrEmpty(service)) info.Service = service;
                    }
                    changed = true;
                }
            }

            if (changed) ItemsRefreshNeeded?.Invoke();
        }

        private async Task<string> GrabServiceAsync(string ip, List<int> open, CancellationToken ct)
        {
            foreach (int port in Options.BannerPorts)
            {
                if (!open.Contains(port)) continue;
                string banner = await _services.Ports.GrabBannerAsync(ip, port, Options.BannerTimeoutMs, ct).ConfigureAwait(false);
                if (!string.IsNullOrEmpty(banner)) return banner;
            }
            return "";
        }

        // 열린 포트 중 위험(백도어) 포트 목록과 일치하는 것이 있는지 확인한다.
        private static bool ContainsProhibitedPort(string portsField, HashSet<int> prohibitedPorts)
        {
            if (string.IsNullOrEmpty(portsField) || prohibitedPorts.Count == 0) return false;
            return ProbeExtensions.ParsePorts(portsField).Any(prohibitedPorts.Contains);
        }

        private void RaiseResultsSummary()
        {
            int alive = 0, dead = 0, total;
            lock (_itemsLock)
            {
                foreach (var info in _items)
                {
                    if (info.Alive) alive++; else dead++;
                }
                total = _items.Count;
            }
            ResultsSummaryChanged?.Invoke(alive, dead, total);
        }

        // 병렬 스캔은 초당 수백 개의 진행 메시지를 만들 수 있어 UI가 밀린다. 일정 간격/개수마다만 내보내고,
        // 마지막 항목은 항상 내보낸다.
        private sealed class MessageThrottle
        {
            private readonly ScanEngine _owner;
            private long _lastTicks;
            private const long IntervalTicks = 150 * TimeSpan.TicksPerMillisecond;

            public MessageThrottle(ScanEngine owner) { _owner = owner; }

            public void Progress(int current, int max, Func<string> build)
            {
                long now = DateTime.UtcNow.Ticks;
                long last = Interlocked.Read(ref _lastTicks);
                if (current != max && now - last < IntervalTicks) return;
                if (Interlocked.CompareExchange(ref _lastTicks, now, last) != last && current != max) return;
                _owner.Message?.Invoke(build());
            }
        }
    }
}
