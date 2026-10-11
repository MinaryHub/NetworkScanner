namespace NetworkScanner.Collector;

// 업로드된 파일 이름/사이트 이름을 저장 경로에 안전하게 쓸 수 있도록 정리한다.
public static class FileNames
{
    public const int MaxLength = 120;

    private static readonly HashSet<char> Invalid = BuildInvalid();
    private static readonly HashSet<string> ReservedWindows = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    };

    private static HashSet<char> BuildInvalid()
    {
        // OS에 상관없이 같은 결과가 나오도록 Windows 금지 문자 집합을 고정으로 쓴다.
        var set = new HashSet<char>(Path.GetInvalidFileNameChars());
        foreach (char c in "<>:\"/\\|?*") set.Add(c);
        return set;
    }

    // 경로 구분자 뒤의 마지막 조각만 쓰고, "..", 제어 문자, 금지 문자를 제거한 뒤 길이를 제한한다.
    public static string Sanitize(string? raw, string fallback = "upload")
    {
        string s = (raw ?? "").Trim();
        int cut = s.LastIndexOfAny(new[] { '/', '\\' });
        if (cut >= 0) s = s.Substring(cut + 1);

        while (s.Contains("..", StringComparison.Ordinal)) s = s.Replace("..", "", StringComparison.Ordinal);

        var sb = new System.Text.StringBuilder(s.Length);
        foreach (char c in s)
        {
            if (char.IsControl(c)) continue;
            sb.Append(Invalid.Contains(c) ? '_' : c);
        }
        s = sb.ToString().Trim().Trim('.', ' ');
        if (s.Length == 0) return fallback;

        string ext = Path.GetExtension(s);
        string stem = s.Substring(0, s.Length - ext.Length);
        if (ReservedWindows.Contains(stem)) stem = "_" + stem;

        if (ext.Length > 16) { ext = ext.Substring(0, 16); }
        if (stem.Length + ext.Length > MaxLength)
            stem = stem.Substring(0, Math.Max(1, MaxLength - ext.Length));
        return stem + ext;
    }

    // 확장자 → 종류. 허용되지 않는 확장자는 "other".
    public static string KindOf(string fileName)
    {
        string ext = Path.GetExtension(fileName).TrimStart('.').ToLowerInvariant();
        return ext switch
        {
            "csv" => "csv",
            "html" => "html",
            "pdf" => "pdf",
            "json" => "json",
            _ => "other",
        };
    }

    public static string ContentTypeOf(string kind) => kind switch
    {
        "csv" => "text/csv; charset=utf-8",
        "html" => "text/html; charset=utf-8",
        "pdf" => "application/pdf",
        "json" => "application/json; charset=utf-8",
        _ => "application/octet-stream",
    };

    // 같은 이름이 이미 있으면 "-2", "-3"… 을 붙여 새 파일을 연다(CreateNew로 경쟁 상태에서도 중복이 없다).
    public static FileStream CreateUnique(string directory, string fileName, out string finalName)
    {
        string ext = Path.GetExtension(fileName);
        string stem = fileName.Substring(0, fileName.Length - ext.Length);
        for (int i = 1; i < 10_000; i++)
        {
            string candidate = i == 1 ? fileName : $"{stem}-{i}{ext}";
            string path = Path.Combine(directory, candidate);
            try
            {
                var fs = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 64 * 1024, useAsync: true);
                finalName = candidate;
                return fs;
            }
            catch (IOException) when (File.Exists(path))
            {
                // 이미 존재 → 다음 번호
            }
        }
        throw new IOException("Too many files with the same name: " + fileName);
    }
}
