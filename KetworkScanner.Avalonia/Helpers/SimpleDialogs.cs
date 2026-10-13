using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;

namespace KetworkScanner.Avalonia.Helpers
{
    // 다중 입력 대화상자의 한 칸. Initial은 미리 채울 값, Watermark는 빈 칸 안내문.
    public sealed record InputField(string Label, string Initial = "", string Watermark = "");

    // Avalonia에는 WPF의 MessageBox 같은 내장 대화상자가 없어, 필요한 최소 기능만 담은 헬퍼.
    public static class SimpleDialogs
    {
        public static async Task ShowMessageAsync(Window owner, string message, string? title = null)
        {
            var dialog = BuildDialog(title ?? Localization.T("dialog.notice"), message, out var buttonPanel);
            var ok = new Button { Content = Localization.T("dialog.ok"), Width = 80 };
            ok.Classes.Add("primary");
            ok.Click += (_, _) => dialog.Close();
            buttonPanel.Children.Add(ok);

            await dialog.ShowDialog(owner);
        }

        public static async Task<bool> ShowConfirmAsync(Window owner, string message, string? title = null)
        {
            var dialog = BuildDialog(title ?? Localization.T("dialog.confirm"), message, out var buttonPanel);
            bool result = false;

            var yes = new Button { Content = Localization.T("dialog.yes"), Width = 80 };
            yes.Classes.Add("primary");
            yes.Click += (_, _) => { result = true; dialog.Close(); };
            var no = new Button { Content = Localization.T("dialog.no"), Width = 80 };
            no.Click += (_, _) => { result = false; dialog.Close(); };
            buttonPanel.Children.Add(yes);
            buttonPanel.Children.Add(no);

            await dialog.ShowDialog(owner);
            return result;
        }

        // 라벨+텍스트박스 여러 줄로 된 입력 대화상자. 취소하면 null, 확인하면 필드 순서대로 값 배열을 돌려준다.
        public static async Task<string[]?> ShowInputAsync(Window owner, string title, params InputField[] fields)
        {
            var buttonPanel = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                HorizontalAlignment = HorizontalAlignment.Right,
                Spacing = 8,
            };

            var form = new Grid { ColumnDefinitions = new ColumnDefinitions("Auto,*"), RowSpacing = 8, ColumnSpacing = 12 };
            var boxes = new TextBox[fields.Length];
            for (int i = 0; i < fields.Length; i++)
            {
                form.RowDefinitions.Add(new RowDefinition(GridLength.Auto));
                var label = new TextBlock { Text = fields[i].Label, VerticalAlignment = VerticalAlignment.Center };
                label.Classes.Add("caption");
                Grid.SetRow(label, i);
                Grid.SetColumn(label, 0);
                form.Children.Add(label);

                boxes[i] = new TextBox { Text = fields[i].Initial, Watermark = fields[i].Watermark, MinWidth = 260 };
                Grid.SetRow(boxes[i], i);
                Grid.SetColumn(boxes[i], 1);
                form.Children.Add(boxes[i]);
            }

            var layout = new StackPanel { Margin = new global::Avalonia.Thickness(16), Spacing = 16 };
            layout.Children.Add(form);
            layout.Children.Add(buttonPanel);

            var dialog = new Window
            {
                Title = title,
                Width = 420,
                SizeToContent = SizeToContent.Height,
                CanResize = false,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Content = layout,
            };

            string[]? result = null;
            var ok = new Button { Content = Localization.T("dialog.ok"), Width = 80 };
            ok.Classes.Add("primary");
            ok.Click += (_, _) =>
            {
                result = new string[boxes.Length];
                for (int i = 0; i < boxes.Length; i++) result[i] = boxes[i].Text ?? "";
                dialog.Close();
            };
            var cancel = new Button { Content = Localization.T("dialog.cancel"), Width = 80 };
            cancel.Click += (_, _) => dialog.Close();
            buttonPanel.Children.Add(ok);
            buttonPanel.Children.Add(cancel);

            if (boxes.Length > 0) dialog.Opened += (_, _) => boxes[0].Focus();
            await dialog.ShowDialog(owner);
            return result;
        }

        private static Window BuildDialog(string title, string message, out StackPanel buttonPanel)
        {
            buttonPanel = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                HorizontalAlignment = HorizontalAlignment.Right,
                Spacing = 8,
            };

            var layout = new StackPanel { Margin = new global::Avalonia.Thickness(16), Spacing = 16 };
            layout.Children.Add(new TextBlock { Text = message, TextWrapping = TextWrapping.Wrap });
            layout.Children.Add(buttonPanel);

            return new Window
            {
                Title = title,
                Width = 360,
                SizeToContent = SizeToContent.Height,
                CanResize = false,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Content = layout,
            };
        }
    }
}
