using System;
using System.Globalization;
using Avalonia.Data.Converters;
using Avalonia.Media;

namespace NetworkScanner.Avalonia.Helpers
{
    // IPInfo.StatusKey("good"/"warn"/"bad")를 상태 색으로 바꾼다. 색 값은 App.axaml의 Up/Risk/Muted와 같다.
    // "warn"은 위험(백도어) 포트가 열린 호스트이므로 레드, 응답 없음은 회색이다.
    public class StatusColorConverter : IValueConverter
    {
        private static readonly ISolidColorBrush Good = new SolidColorBrush(Color.Parse("#FF15803D"));
        private static readonly ISolidColorBrush Warn = new SolidColorBrush(Color.Parse("#FFB91C1C"));
        private static readonly ISolidColorBrush Bad = new SolidColorBrush(Color.Parse("#FF8A97A4"));

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
        private static readonly ISolidColorBrush Risk = new SolidColorBrush(Color.Parse("#FFFDECEA"));
        private static readonly ISolidColorBrush Plain = new SolidColorBrush(Colors.White);

        public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
            => (value as string) == "warn" ? Risk : Plain;

        public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
            => throw new NotSupportedException();
    }

    // 응답 없는 호스트의 글자는 회색으로 물러나게 한다.
    public class StatusForegroundConverter : IValueConverter
    {
        private static readonly ISolidColorBrush Ink = new SolidColorBrush(Color.Parse("#FF14202B"));
        private static readonly ISolidColorBrush Muted = new SolidColorBrush(Color.Parse("#FF8A97A4"));

        public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
            => (value as string) == "bad" ? Muted : Ink;

        public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
            => throw new NotSupportedException();
    }
}
