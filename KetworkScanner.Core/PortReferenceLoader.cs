using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace KetworkScanner
{
    // reservedports.ini/prohibitports.ini를 읽어 참조 포트 목록을 만든다.
    // GUI/CLI가 공유하며, UI는 반환된 목록을 각자의 리스트 컨트롤에 표시하기만 하면 된다.
    public static class PortReferenceLoader
    {
        public static Action<string>? OnError { get; set; }

        public static (List<RefPortInfo> Reserved, List<RefPortInfo> Prohibited) Load()
        {
            var prohibited = new List<RefPortInfo>();
            var reserved = new List<RefPortInfo>();

            try
            {
                string[] prohibitContents = File.ReadAllLines(DataPaths.Resolve("prohibitports.ini"), Encoding.UTF8);
                foreach (string s in prohibitContents)
                {
                    if (string.IsNullOrWhiteSpace(s)) continue;

                    // Split(',', 2)로 제한하여 설명에 콤마가 포함된 줄(예: "50766,Fore, Schwindler")도
                    // 이름 필드가 잘리지 않도록 한다.
                    string[] token = s.Split(',', 2);
                    if (token.Length < 2 || !int.TryParse(token[0].Trim(), out int portNo)) continue;

                    prohibited.Add(new RefPortInfo { Protocol = "", PortNo = portNo, Portname = token[1].Trim() });
                }
            }
            catch (Exception ex)
            {
                OnError?.Invoke(string.Format(Localization.T("msg.store.loadfailed"), "prohibitports.ini", ex.Message));
            }

            try
            {
                string[] reservedContents = File.ReadAllLines(DataPaths.Resolve("reservedports.ini"), Encoding.UTF8);
                foreach (string s in reservedContents)
                {
                    if (string.IsNullOrWhiteSpace(s)) continue;

                    // Split(',', 3)으로 제한하여 설명에 콤마가 포함된 줄도 이름 필드가 잘리지 않도록 한다.
                    string[] token = s.Split(',', 3);
                    if (token.Length < 3 || !int.TryParse(token[1].Trim(), out int portNo)) continue;

                    reserved.Add(new RefPortInfo { Protocol = token[0].Trim(), PortNo = portNo, Portname = token[2].Trim() });
                }
            }
            catch (Exception ex)
            {
                OnError?.Invoke(string.Format(Localization.T("msg.store.loadfailed"), "reservedports.ini", ex.Message));
            }

            return (reserved, prohibited);
        }
    }
}
