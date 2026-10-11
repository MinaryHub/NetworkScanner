using System;
using System.Globalization;
using Avalonia.Data.Converters;

namespace NetworkScanner.Avalonia.Helpers
{
    // 위험 점수(0..100)를 표에 보일 문자열로. 0은 "평가 없음/문제 없음"이라 빈칸으로 둬 표가 조용해진다.
    public class RiskScoreConverter : IValueConverter
    {
        public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
            => value is int score && score > 0 ? score.ToString(CultureInfo.InvariantCulture) : "";

        public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
            => throw new NotSupportedException();
    }

    // true → "✓", false → 빈칸. 승인 여부 같은 불리언 컬럼에 쓴다.
    public class BoolCheckConverter : IValueConverter
    {
        public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
            => value is true ? "✓" : "";

        public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
            => throw new NotSupportedException();
    }
}
