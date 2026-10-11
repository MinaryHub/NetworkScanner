using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace NetworkScanner
{
    // 사용자가 직접 입력한 이름/비고를 IP 기준으로 파일에 보관해, 재스캔·재시작 후에도 유지·병합되게 한다.
    // 스캔은 이름/비고를 덮어쓰지 않으므로, 여기 저장된 값을 새 스캔 결과에 다시 채워 넣는 역할을 한다.
    public static class AnnotationStore
    {
        public const string FileName = "annotations.ini";
        public static Action<string>? OnError { get; set; }

        public sealed record Annotation(string Name, string Description);

        public static Dictionary<string, Annotation> Load()
        {
            var map = new Dictionary<string, Annotation>();
            string path = UserDataPaths.Resolve(FileName);
            if (!File.Exists(path)) return map;

            try
            {
                foreach (string line in File.ReadAllLines(path, Encoding.UTF8))
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    // 탭 구분(이름/비고에 콤마가 들어갈 수 있어 CSV 대신 탭 사용). ip \t name \t description
                    string[] token = line.Split('\t');
                    if (token.Length < 3) continue;
                    map[token[0]] = new Annotation(token[1], token[2]);
                }
            }
            catch (Exception ex)
            {
                OnError?.Invoke(string.Format(Localization.T("msg.store.loadfailed"), FileName, ex.Message));
            }
            return map;
        }

        public static void Save(IEnumerable<IPInfo> items)
        {
            try
            {
                var lines = new List<string>();
                foreach (IPInfo i in items)
                {
                    string name = i.SystemName ?? "";
                    string desc = i.Description ?? "";
                    if (string.IsNullOrEmpty(name) && string.IsNullOrEmpty(desc)) continue;
                    // 탭/개행이 값에 섞이면 형식이 깨지므로 공백으로 치환한다.
                    lines.Add($"{i.Ip}\t{Clean(name)}\t{Clean(desc)}");
                }
                File.WriteAllLines(UserDataPaths.Resolve(FileName), lines, Encoding.UTF8);
            }
            catch (Exception ex)
            {
                OnError?.Invoke(string.Format(Localization.T("msg.store.savefailed"), FileName, ex.Message));
            }
        }

        private static string Clean(string s) => s.Replace('\t', ' ').Replace('\n', ' ').Replace('\r', ' ');
    }
}
