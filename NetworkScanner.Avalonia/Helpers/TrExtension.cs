using System;
using Avalonia.Markup.Xaml;

namespace NetworkScanner.Avalonia.Helpers
{
    // XAML에서 {helpers:Tr Key=some.key} 형태로 현재 언어의 문자열을 얻는 마크업 확장.
    // 언어는 앱 시작 시 고정되므로(전환은 재시작 반영) 로드 시점에 한 번 평가하면 된다.
    public class TrExtension : MarkupExtension
    {
        public string Key { get; set; } = "";

        public override object ProvideValue(IServiceProvider serviceProvider) => Localization.T(Key);
    }
}
