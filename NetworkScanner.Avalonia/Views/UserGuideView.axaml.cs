using Avalonia.Controls;
using Avalonia.Media;

namespace NetworkScanner.Avalonia.Views;

// 사용 설명서 화면. 콘텐츠는 Core의 UserGuide가 언어별로 제공하고,
// 여기서는 언어 콤보 선택에 따라 섹션들을 다시 그리기만 한다.
public partial class UserGuideView : UserControl
{
    private static readonly IBrush HeadingBrush = new SolidColorBrush(Color.Parse("#FF0F766E"));
    private static readonly IBrush BodyBrush = new SolidColorBrush(Color.Parse("#FF14202B"));

    public UserGuideView()
    {
        InitializeComponent();

        foreach (var (_, displayName) in UserGuide.Languages)
        {
            CbLanguage.Items.Add(displayName);
        }
        CbLanguage.SelectedIndex = IndexOfLanguage(UserGuide.DefaultLanguage);
    }

    private static int IndexOfLanguage(string code)
    {
        for (int i = 0; i < UserGuide.Languages.Length; i++)
        {
            if (UserGuide.Languages[i].Code == code) return i;
        }
        return 0;
    }

    private void CbLanguage_SelectionChanged(object? sender, SelectionChangedEventArgs e)
    {
        int index = CbLanguage.SelectedIndex;
        if (index < 0 || index >= UserGuide.Languages.Length) return;
        Render(UserGuide.Languages[index].Code);
    }

    private void Render(string lang)
    {
        PnlSections.Children.Clear();
        foreach (var section in UserGuide.GetSections(lang))
        {
            PnlSections.Children.Add(new TextBlock
            {
                Text = section.Heading,
                FontSize = 17,
                FontWeight = FontWeight.Bold,
                Foreground = HeadingBrush,
                Margin = new global::Avalonia.Thickness(0, 14, 0, 2),
            });
            PnlSections.Children.Add(new TextBlock
            {
                Text = section.Body,
                Foreground = BodyBrush,
                TextWrapping = TextWrapping.Wrap,
                LineHeight = 22,
            });
        }
    }
}
