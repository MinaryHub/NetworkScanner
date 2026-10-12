using System;
using System.Globalization;
using Avalonia;
using Avalonia.Data.Converters;
using Avalonia.Media;

namespace NetworkScanner.Avalonia.Helpers
{
    // App.axaml의 테마 브러시를 이름으로 찾는다. 리소스가 없으면(디자이너/테스트) 같은 값의 기본색으로 대신한다.
    internal static class ThemeBrushes
    {
        public static IBrush Get(string key, string fallbackHex)
        {
            try
            {
                if (Application.Current?.Resources.TryGetResource(key, null, out object? value) == true && value is IBrush brush)
                    return brush;
            }
            catch
            {
                // 리소스 조회 실패는 색만 기본값으로 돌아가면 된다.
            }
            return new SolidColorBrush(Color.Parse(fallbackHex));
        }
    }

    // IPInfo.StatusKey("good"/"warn"/"bad")를 상태 색으로 바꾼다. 색은 App.axaml의 Up/Risk/Muted 브러시다.
    // "warn"은 위험(백도어) 포트가 열렸거나 위험 점수가 높은 호스트이므로 레드, 응답 없음은 회색이다.
    public class StatusColorConverter : IValueConverter
    {
        private static readonly IBrush Good = ThemeBrushes.Get("UpBrush", "#FF15803D");
        private static readonly IBrush Warn = ThemeBrushes.Get("RiskBrush", "#FFB91C1C");
        private static readonly IBrush Bad = ThemeBrushes.Get("MutedBrush", "#FF8A97A4");

        public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            return (value as string) switch
            {
                "good" => Good,
                "warn" => Warn,
                _ => Bad,
            };
        }

        public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            throw new NotSupportedException();
        }
    }

    // StatusKey가 ConverterParameter와 같을 때만 true. 상태별 도형(원/삼각/빈 원)을 골라 보여주는 데 쓴다.
    public class StatusKeyIsConverter : IValueConverter
    {
        public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
            => string.Equals(value as string, parameter as string, StringComparison.Ordinal);

        public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
            => throw new NotSupportedException();
    }

    // 위험 행만 옅은 레드 배경을 준다(화면에서 유일한 "뜨거운" 면). 나머지 행은 흰색 그대로.
    public class StatusRowBackgroundConverter : IValueConverter
    {
        private static readonly IBrush Risk = ThemeBrushes.Get("RiskTintBrush", "#FFFDECEA");
        private static readonly IBrush Plain = ThemeBrushes.Get("SurfaceBrush", "#FFFFFFFF");

        public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
            => (value as string) == "warn" ? Risk : Plain;

        public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
            => throw new NotSupportedException();
    }

    // 응답 없는 호스트의 글자는 회색으로 물러나게 한다.
    public class StatusForegroundConverter : IValueConverter
    {
        private static readonly IBrush Ink = ThemeBrushes.Get("InkBrush", "#FF14202B");
        private static readonly IBrush Muted = ThemeBrushes.Get("MutedBrush", "#FF8A97A4");

        public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
            => (value as string) == "bad" ? Muted : Ink;

        public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
            => throw new NotSupportedException();
    }
}
