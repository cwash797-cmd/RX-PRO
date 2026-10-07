using System.Diagnostics;
using System.IO;
using System.Windows;
using RxPro.Core;

namespace RxPro.Windows;

public static class Program
{
    [STAThread]
    public static int Main(string[] args)
    {
        if (args.Length == 3 && args[0] == "--watchdog" && int.TryParse(args[1], out var pid) && long.TryParse(args[2], out var ticks))
            return Watch(pid, ticks);
        if (args.Length != 0) return 2; // Do not accept secrets or arbitrary configs on the command line.
        try
        {
            var store = new PrivateStore();
            using var instance = store.Lock();
            var proxy = new ProxyLease(new WindowsProxy(), store);
            var conflict = proxy.Recover();
            using var watcher = StartWatcher(); // Must be alive BEFORE any proxy state is changed.
            var app = new Application { ShutdownMode = ShutdownMode.OnMainWindowClose };
            var window = new MainWindow(store, proxy, watcher);
            app.DispatcherUnhandledException += (_, e) => { e.Handled = true; window.EmergencyStop(); };
            if (conflict) window.SetNotice("Прокси менялся другим приложением: чужие настройки сохранены.");
            return app.Run(window);
        }
        catch
        {
            MessageBox.Show("Не удалось открыть RX-PRO. Возможно, он уже запущен, данные принадлежат другому пользователю или требуется восстановление прокси. Проверьте настройки Windows → Сеть → Прокси. Секреты не выводятся.", "RX-PRO Windows", MessageBoxButton.OK, MessageBoxImage.Warning);
            return 1;
        }
    }
    private static Process StartWatcher()
    {
        var current = Process.GetCurrentProcess();
        var start = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = false, CreateNoWindow = true };
        start.ArgumentList.Add("--watchdog"); start.ArgumentList.Add(current.Id.ToString()); start.ArgumentList.Add(current.StartTime.ToUniversalTime().Ticks.ToString());
        return Process.Start(start) ?? throw new IOException("Не удалось запустить восстановление прокси.");
    }
    public static int Watch(int parentId, long startTicks)
    {
        try
        {
            try
            {
                using var parent = Process.GetProcessById(parentId);
                if (parent.StartTime.ToUniversalTime().Ticks == startTicks) parent.WaitForExit();
            }
            catch (ArgumentException) { }
            var store = new PrivateStore();
            // If a new GUI already holds the lock, it owns recovery; never touch its connection.
            using var instance = store.Lock();
            new ProxyLease(new WindowsProxy(), store).Recover();
            return 0;
        }
        catch { return 1; } // The encrypted journal remains for recovery on next launch.
    }
}
