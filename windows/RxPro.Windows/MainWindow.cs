using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using RxPro.Core;

namespace RxPro.Windows;

public sealed class MainWindow : Window
{
    private readonly PrivateStore store;
    private readonly ProxyLease proxy;
    private readonly Process watcher;
    private readonly ListBox profiles = new() { MinHeight = 140 };
    private readonly Button connect = new() { Content = "Подключить", Padding = new Thickness(24, 12, 24, 12) };
    private readonly Button import = new() { Content = "Добавить ссылку", Padding = new Thickness(12, 7, 12, 7) };
    private readonly Button remove = new() { Content = "Удалить", Padding = new Thickness(12, 7, 12, 7) };
    private readonly Button check = new() { Content = "Проверить через прокси", Padding = new Thickness(12, 7, 12, 7), IsEnabled = false };
    private readonly CheckBox systemProxy = new() { Content = "Использовать системный прокси Windows", Margin = new Thickness(0, 16, 0, 12), IsChecked = false };
    private readonly TextBlock status = new() { Text = "Не подключено", FontSize = 24, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 10, 0, 12) };
    private readonly TextBlock notice = new() { TextWrapping = TextWrapping.Wrap, Foreground = Brushes.DimGray, Margin = new Thickness(0, 12, 0, 0) };
    private readonly TextBlock ports = new() { TextWrapping = TextWrapping.Wrap };
    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly DispatcherTimer timer = new() { Interval = TimeSpan.FromSeconds(1) };
    private List<SavedProfile> saved;
    private CancellationTokenSource? cancellation;
    private CoreHost? core;
    private int httpPort, socksPort;
    private bool closing, closed;
    public MainWindow(PrivateStore store, ProxyLease proxy, Process watcher)
    {
        this.store = store; this.proxy = proxy; this.watcher = watcher;
        saved = store.Profiles(); Title = "RX-PRO Windows · S3"; Width = 840; Height = 580;
        MinWidth = 700; MinHeight = 500; WindowStartupLocation = WindowStartupLocation.CenterScreen;
        Background = new SolidColorBrush(Color.FromRgb(243, 246, 250)); FontFamily = new FontFamily("Segoe UI"); FontSize = 14;
        var root = new DockPanel { Margin = new Thickness(28) }; Content = root;
        var heading = new StackPanel { Margin = new Thickness(0, 0, 0, 22) };
        heading.Children.Add(new TextBlock { Text = "RX-PRO", FontSize = 32, FontWeight = FontWeights.Bold, Foreground = new SolidColorBrush(Color.FromRgb(24, 51, 83)) });
        heading.Children.Add(new TextBlock { Text = "WINDOWS  /  S3  /  0.1.0-rc1", Foreground = Brushes.SlateGray, Margin = new Thickness(0, 5, 0, 0) });
        DockPanel.SetDock(heading, Dock.Top); root.Children.Add(heading);
        var footer = new TextBlock { Text = "Прокси-режим, не TUN. Программы, игнорирующие прокси, могут выходить напрямую.\nПрофили защищены учётной записью Windows. Не отправляйте ссылки и ключи в поддержку.", TextWrapping = TextWrapping.Wrap,
            Foreground = Brushes.SlateGray, FontSize = 12, Margin = new Thickness(0, 22, 0, 0) };
        DockPanel.SetDock(footer, Dock.Bottom); root.Children.Add(footer);
        var columns = new Grid(); columns.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(260) });
        columns.ColumnDefinitions.Add(new ColumnDefinition()); root.Children.Add(columns);
        var left = new StackPanel { Margin = new Thickness(0, 0, 24, 0) };
        left.Children.Add(new TextBlock { Text = "Профили", FontSize = 18, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 12) });
        left.Children.Add(profiles);
        var buttons = new WrapPanel { Margin = new Thickness(0, 12, 0, 0) }; buttons.Children.Add(import); buttons.Children.Add(remove); left.Children.Add(buttons);
        columns.Children.Add(left);
        var right = new StackPanel(); Grid.SetColumn(right, 1); columns.Children.Add(new Border { Child = right, Padding = new Thickness(20), Background = Brushes.White, CornerRadius = new CornerRadius(10) });
        Grid.SetColumn(columns.Children[^1], 1);
        right.Children.Add(status); right.Children.Add(ports); right.Children.Add(systemProxy); right.Children.Add(connect);
        check.Margin = new Thickness(0, 12, 0, 0); right.Children.Add(check); right.Children.Add(notice);
        profiles.ItemsSource = saved; if (saved.Count > 0) profiles.SelectedIndex = 0;
        notice.Text = "Добавьте S3-ссылку из менеджера. Телефон может просто раздавать интернет — VPN на нём для этого не требуется.";
        import.Click += (_, _) => Import(); remove.Click += (_, _) => Remove(); connect.Click += async (_, _) => await Toggle();
        check.Click += async (_, _) => await Check();
        timer.Tick += async (_, _) => { if (core != null && !gate.CurrentCount.Equals(0) && (!core.Running || watcher.HasExited)) { SetNotice("Процесс остановился. Выполняется восстановление прокси."); await Stop(); } };
        timer.Start();
        Closing += async (_, e) => {
            if (closed) return;
            e.Cancel = true;
            if (closing) return;
            closing = true; IsEnabled = false;
            await Stop();
            closed = true; timer.Stop();
            // Stop() can complete synchronously while the original Closing event
            // is still on the stack. WPF forbids reentrant Close(): queue it instead.
            _ = Dispatcher.BeginInvoke(new Action(Close), DispatcherPriority.Normal);
        };
    }
    public void SetNotice(string value) => notice.Text = value;
    public async void EmergencyStop() { SetNotice("Операция прервана. Выполняется безопасное отключение."); await Stop(); }
    private void Import()
    {
        var dialog = new Window { Title = "Добавить S3-профиль", Owner = this, Width = 550, Height = 245, ResizeMode = ResizeMode.NoResize, WindowStartupLocation = WindowStartupLocation.CenterOwner };
        var panel = new StackPanel { Margin = new Thickness(22) }; dialog.Content = panel;
        panel.Children.Add(new TextBlock { Text = "Вставьте ссылку менеджера. Она содержит секретные ключи.", TextWrapping = TextWrapping.Wrap });
        var input = new PasswordBox { MaxLength = 16384, Margin = new Thickness(0, 14, 0, 14) }; panel.Children.Add(input);
        var actions = new WrapPanel(); panel.Children.Add(actions);
        var paste = new Button { Content = "Вставить из буфера", Padding = new Thickness(12, 8, 12, 8) };
        var add = new Button { Content = "Добавить", Padding = new Thickness(12, 8, 12, 8) }; actions.Children.Add(paste); actions.Children.Add(add);
        paste.Click += (_, _) => { try { input.Password = Clipboard.GetText(); } catch { MessageBox.Show(dialog, "Буфер обмена недоступен."); } };
        add.Click += (_, _) => {
            try {
                var link = input.Password.Trim(); var parsed = S3Profile.Parse(link);
                if (saved.Count >= 100) throw new InvalidOperationException();
                if (saved.Any(p => S3Profile.Parse(p.Link).Uuid == parsed.Uuid)) { MessageBox.Show(dialog, "Такой UUID уже добавлен. Для обновления удалите прежний профиль."); return; }
                var next = new List<SavedProfile>(saved) { new() { Link = link } };
                store.Write("profiles.dpapi", next); saved = next; profiles.ItemsSource = saved; profiles.SelectedIndex = saved.Count - 1;
                input.Clear(); dialog.DialogResult = true;
            } catch { MessageBox.Show(dialog, "Не удалось импортировать. Проверьте S3-ссылку и доступ к защищённому хранилищу."); }
        };
        dialog.ShowDialog(); input.Clear();
    }
    private void Remove()
    {
        if (profiles.SelectedItem is not SavedProfile p) return;
        if (MessageBox.Show(this, "Удалить локальный профиль? Доступ на сервере не отзывается.", "RX-PRO", MessageBoxButton.YesNo) != MessageBoxResult.Yes) return;
        try { var next = saved.Where(x => x.Id != p.Id).ToList(); store.Write("profiles.dpapi", next); saved = next; profiles.ItemsSource = saved; if (saved.Count > 0) profiles.SelectedIndex = 0; }
        catch { SetNotice("Не удалось сохранить список профилей."); }
    }
    private void Controls(bool idle)
    {
        profiles.IsEnabled = import.IsEnabled = remove.IsEnabled = systemProxy.IsEnabled = idle;
        check.IsEnabled = !idle && core?.Running == true; connect.Content = idle ? "Подключить" : "Отключить / отменить";
    }
    private async Task Toggle()
    {
        if (cancellation != null || core != null) { await Stop(); return; }
        if (profiles.SelectedItem is not SavedProfile p) { SetNotice("Сначала выберите профиль."); return; }
        if (systemProxy.IsChecked == true && MessageBox.Show(this,
            "Временно заменить системный прокси и PAC/автообнаружение? При отключении прежние настройки будут восстановлены, если их не изменит другая программа.",
            "Системный прокси", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
        await gate.WaitAsync(); cancellation = new CancellationTokenSource(); Controls(false); status.Text = "Запуск…";
        try
        {
            if (watcher.HasExited) throw new IOException();
            httpPort = CoreHost.FreePort(); do { socksPort = CoreHost.FreePort(); } while (socksPort == httpPort);
            var parsed = S3Profile.Parse(p.Link);
            core = new CoreHost(Path.Combine(AppContext.BaseDirectory, "core", "xray-s3.exe"), CoreHost.EmbeddedHash());
            await core.StartAsync(parsed.CreateConfig(httpPort, socksPort), httpPort, socksPort, cancellation.Token);
            cancellation.Token.ThrowIfCancellationRequested();
            if (systemProxy.IsChecked == true) { WindowsProxy.CheckPolicy(); proxy.Apply(httpPort); }
            status.Text = "Прокси запущен"; ports.Text = $"HTTP  127.0.0.1:{httpPort}\nSOCKS5  127.0.0.1:{socksPort}";
            check.IsEnabled = true; SetNotice("Локальные порты готовы. Это ещё не подтверждение доступа к VK или серверу: выполните проверку.");
        }
        catch
        {
            bool restored = Cleanup(); Controls(true); status.Text = restored ? "Не подключено" : "Проверьте прокси Windows";
            if (restored) SetNotice("Запуск отменён или не удался. Проверьте полный ZIP, профиль, доступность портов и политику прокси. Секреты не выводятся.");
        }
        finally { gate.Release(); }
    }
    private bool Cleanup()
    {
        bool restored = true;
        try { if (proxy.Recover()) SetNotice("Прокси изменён другой программой; её настройки оставлены без изменений."); } catch { restored = false; }
        core?.Dispose(); core = null; cancellation?.Dispose(); cancellation = null;
        if (!restored) SetNotice("Не удалось восстановить прокси. Журнал сохранён; повторно откройте RX-PRO или проверьте настройки прокси Windows.");
        return restored;
    }
    private async Task Stop()
    {
        cancellation?.Cancel(); await gate.WaitAsync();
        try { bool ok = Cleanup(); Controls(true); ports.Text = ""; status.Text = ok ? "Не подключено" : "Проверьте прокси Windows"; }
        finally { gate.Release(); }
    }
    private async Task Check()
    {
        if (core?.Running != true || cancellation == null) return;
        check.IsEnabled = false; SetNotice("Проверка HTTPS через локальный прокси…");
        try
        {
            using var handler = new HttpClientHandler { Proxy = new WebProxy("http://127.0.0.1:" + httpPort), UseProxy = true, AllowAutoRedirect = false, UseCookies = false };
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
            using var response = await client.GetAsync("https://www.gstatic.com/generate_204", HttpCompletionOption.ResponseHeadersRead, cancellation.Token);
            SetNotice(response.StatusCode == HttpStatusCode.NoContent ? "HTTPS через прокси работает. Это проверка доступности, не скорости." : "Проверочный сайт ответил иначе. Доступность других сайтов проверьте в браузере.");
        }
        catch { SetNotice("HTTPS-проверка не прошла: возможны проблемы сети, VK, ключей, сервера или проверочного сайта. Прямой fallback не используется."); }
        finally { check.IsEnabled = core?.Running == true; }
    }
}
