using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace NetworkScanner
{
    public class OUIInfo
    {
        // 플랫폼 종속적인 로깅(Windows 이벤트 로그 등)에 직접 의존하지 않기 위해,
        // 오류 발생 시 호출할 콜백을 호스트 애플리케이션이 선택적으로 등록할 수 있게 한다.
        public static Action<string>? OnError { get; set; }

        Dictionary<string, string> _OUIInfo = new Dictionary<string, string>();
        public OUIInfo()
        {

        }

        public void LoadInfo()
        {
            string[] sContents;
            try
            {
                sContents = File.ReadAllLines(DataPaths.Resolve("ouiinfo.ini"), Encoding.UTF8);
            }
            catch (Exception ex)
            {
                OnError?.Invoke(string.Format(Localization.T("msg.store.loadfailed"), "ouiinfo.ini", ex.Message));
                return;
            }

            foreach (string s in sContents)
            {
                if (!s.Contains("(hex)")) continue;

                try
                {
                    string filter = s.Replace("(hex)", ":");
                    string[] token = filter.Split(':');
                    if (token.Length < 2) continue;

                    _OUIInfo[token[0].Trim()] = token[1].Trim();
                }
                catch (Exception ex)
                {
                    OnError?.Invoke(string.Format(Localization.T("msg.parse.skipped"), "ouiinfo.ini", ex.Message));
                }
            }
        }

        public string GetVender(string mac)
        {
            try
            {
                if (IsValidMac(mac))
                {
                    string oui = mac.Substring(0, 8);

                    if (_OUIInfo.ContainsKey(oui))
                    {
                        return _OUIInfo[oui];
                    }
                    else
                        return "";
                }
            }
            catch (Exception ex)
            {
                OnError?.Invoke(ex.Message);
            }

            return "";
        }

        public bool IsValidMac(string mac)
        {
            if (mac == null || mac.Length == 0)
                return false;
            else
                return true;
        }


    }
}
