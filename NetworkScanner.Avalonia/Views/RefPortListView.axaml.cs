using System;
using System.Collections.Generic;
using Avalonia.Controls;
using Avalonia.Interactivity;

namespace NetworkScanner.Avalonia.Views
{
    public partial class RefPortListView : UserControl
    {
        public List<RefPortInfo> ReservedPortList { get; private set; } = new List<RefPortInfo>();
        public List<RefPortInfo> ProhibitPortList { get; private set; } = new List<RefPortInfo>();

        // "지금 갱신" 버튼. MainWindow가 ReferenceDataUpdater를 돌리고 LoadInfo()/ShowStatus()로 결과를 반영한다.
        public event Action? UpdateRequested;

        public RefPortListView()
        {
            InitializeComponent();
            LoadInfo();
        }

        public void ShowStatus(string text) => TbRefStatus.Text = text;
        public void SetBusy(bool busy) => BtnRefUpdate.IsEnabled = !busy;
        private void BtnRefUpdate_Click(object? sender, RoutedEventArgs e) => UpdateRequested?.Invoke();

        public void LoadInfo()
        {
            var (reserved, prohibited) = PortReferenceLoader.Load();

            ReservedPortList = reserved;
            ProhibitPortList = prohibited;

            LbOpenPortList.ItemsSource = ReservedPortList;
            LbProhibitPortList.ItemsSource = ProhibitPortList;
        }
    }
}
