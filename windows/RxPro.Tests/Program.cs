using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Windows;
using System.Windows.Threading;
using RxPro.Core;
using RxPro.Windows;

static class Tests
{
    static int count;
    static void Need(bool condition, string label) { if (!condition) throw new Exception(label); count++; }
    static void Reject(Action action, string label) { try { action(); } catch (ProfileException e) { Need(!e.ToString().Contains("fixture-secret"), "secret-safe errors"); count++; return; } throw new Exception(label); }
    static string Link(string encryption = "mlkem768x25519plus.native.1rtt.fixture", Action<JsonObject>? edit = null)
    {
        var data = new JsonObject { ["version"] = 1, ["endpoint"] = "https://hb.ru-msk.vkcloud-storage.ru", ["region"] = "ru-msk",
            ["bucket"] = "fixture-bucket", ["prefix"] = "rxs3/aaaaaaaaaaaaaaaaaaaaaaaa/bbbbbbbbbbbbbbbbbbbbbbbb/g1/",
            ["accessKey"] = "fixture-access", ["secretKey"] = "fixture-secret" };
        edit?.Invoke(data);
        var payload = Convert.ToBase64String(Encoding.UTF8.GetBytes(data.ToJsonString())).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        return "vless://11111111-2222-4333-8444-555555555555@hb.ru-msk.vkcloud-storage.ru:443?type=xdrive&service=s3&encryption=" + Uri.EscapeDataString(encryption) + "&s3=" + payload + "#Windows%20test";
    }
    sealed class Settings : IProxySettings
    {
        public Dictionary<string, ProxyValue?> Values = new() { ["Flags"] = new("DWord", "13"), ["ProxyServer"] = new("String", "old:1234"), ["ProxyOverride"] = new("String", "*.internal"), ["AutoConfigURL"] = new("String", "http://127.0.0.1:9/proxy.pac") };
        public bool Partial;
        public Dictionary<string, ProxyValue?> Read() => new(Values);
        public void Write(Dictionary<string, ProxyValue?> values)
        {
            if (Partial) { Values["ProxyServer"] = values["ProxyServer"]; Partial = false; throw new IOException(); }
            Values = new(values);
        }
    }
    sealed class Journal : IProxyJournal
    {
        public ProxyJournal? Value; public bool Fail;
        public ProxyJournal? Load() => Value;
        public void Save(ProxyJournal value) { if (Fail) throw new IOException(); Value = value; }
        public void Delete() => Value = null;
    }
    static bool Same(Dictionary<string, ProxyValue?> a, Dictionary<string, ProxyValue?> b) => a.Count == b.Count && a.All(p => b.GetValueOrDefault(p.Key) == p.Value);
    static void Unit()
    {
        var link = Link(); var profile = S3Profile.Parse(link); Need(profile.Name == "Windows test", "readable name");
        Need(profile.Uuid.ToString() == "11111111-2222-4333-8444-555555555555", "preserved UUID");
        Need(!profile.ToString().Contains("secret"), "safe profile display");
        foreach (var bad in new[] { link.Replace("vless:", "http:"), link.Replace(":443?", ":80?"), link.Replace("service=s3", "service=other"),
                     link.Replace("1rtt", "0rtt"), link.Replace("type=xdrive", "type=xdrive&type=tcp"), link.Replace("type=xdrive", "type=xdrive&%74ype=xdrive"),
                     link.Replace("#Windows%20test", "&security=tls"), link.Replace("#Windows%20test", "&flow=vision"),
                     link.Replace("#Windows%20test", "&extra=ignored"), link.Replace("11111111-2222-4333-8444-555555555555", "invalid"),
                     Link(edit: x => x["endpoint"] = "https://attacker.invalid"), Link(edit: x => x["version"] = 2),
                     Link(edit: x => x["region"] = "other"), Link(edit: x => x["prefix"] = "../escape"),
                     Link(edit: x => x["secretKey"] = "fixture-secret\n"), Link(edit: x => x["extra"] = "no"), new string('x', 16385) })
            Reject(() => S3Profile.Parse(bad), "rejected unsafe link");
        Need(S3Profile.Parse(link.Replace("Windows%20test", Uri.EscapeDataString("vless://secret"))).Name == "VK S3", "credential title redacted");
        var config = JsonNode.Parse(profile.CreateConfig(22080, 22081))!;
        Need(config["outbounds"]!.AsArray().Count == 1, "no direct fallback");
        var stream = config["outbounds"]![0]!["streamSettings"]!;
        Need(stream["address"]!.GetValue<string>() == S3Profile.BootstrapAddress, "fixed bootstrap without external DNS");
        Need(stream["xdriveSettings"]!["sessionTtlSeconds"]!.GetValue<int>() == 300, "client TTL remains compatible");
        Need(config["inbounds"]!.AsArray().All(x => x!["listen"]!.GetValue<string>() == "127.0.0.1"), "no LAN listener");
        Reject(() => profile.CreateConfig(1234, 1234), "same ports rejected");
        var settings = new Settings(); var journal = new Journal(); var lease = new ProxyLease(settings, journal); var original = settings.Read();
        lease.Apply(22080); Need(settings.Values["Flags"]!.Value == "3", "PAC/WPAD disabled during owned proxy");
        Need(journal.Value != null, "journal exists while active"); lease.Recover(); Need(Same(settings.Read(), original), "prior PAC and settings restored");
        Need(!lease.Recover(), "idempotent recovery"); journal.Fail = true;
        try { lease.Apply(22080); throw new Exception("journal failure should stop apply"); } catch (IOException) { }
        Need(Same(settings.Read(), original), "no mutation before durable journal"); journal.Fail = false; settings.Partial = true;
        try { lease.Apply(22080); } catch (IOException) { }
        lease.Recover(); Need(Same(settings.Read(), original), "partial write crash recovered");
        lease.Apply(22080); settings.Values["ProxyServer"] = new("String", "another-vpn:9000"); var external = settings.Read();
        Need(lease.Recover() && Same(settings.Read(), external), "external proxy owner not overwritten");
        Console.WriteLine("PASS: strict manager-link import, secret-safe errors, exact configuration and proxy crash/ownership model");
    }
    static void Storage(string work)
    {
        var store = new PrivateStore(Path.Combine(work, "private"));
        var values = new List<SavedProfile> { new() { Link = Link() } }; store.Write("profiles.dpapi", values);
        Need(store.Profiles()[0].Link == values[0].Link, "DPAPI round trip");
        var file = Path.Combine(store.Root, "profiles.dpapi");
        Need(!Encoding.UTF8.GetString(File.ReadAllBytes(file)).Contains("vless://"), "no plaintext credential file");
        Need(new DirectoryInfo(store.Root).GetAccessControl().AreAccessRulesProtected, "private ACL inheritance disabled");
        using (var locked = store.Lock()) { try { using var duplicate = store.Lock(); throw new Exception("duplicate allowed"); } catch (IOException) { count++; } }
        var data = File.ReadAllBytes(file); data[^1] ^= 1; File.WriteAllBytes(file, data);
        try { store.Profiles(); throw new Exception("tampering accepted"); } catch (IOException) { count++; }
        Console.WriteLine("PASS: actual Windows DPAPI, restricted ACL, tamper rejection and single-instance lock");
    }
    static void SystemProxy(string work)
    {
        if (Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true") throw new Exception("Real proxy tests require disposable CI runner");
        var windows = new WindowsProxy(); var original = windows.Read();
        try
        {
            var prior = new Dictionary<string, ProxyValue?>(original) { ["Flags"] = new("DWord", "5"), ["AutoConfigURL"] = new("String", "http://127.0.0.1:9/fixture.pac") };
            windows.Write(prior); prior = windows.Read();
            var store = new PrivateStore(Path.Combine(work, "proxy")); var lease = new ProxyLease(windows, store);
            lease.Apply(22080); Need(windows.Read()["ProxyServer"]!.Value.Contains("22080"), "real system proxy applied");
            Need(windows.Read()["Flags"]!.Value == "3", "real PAC flags suppressed");
            new ProxyLease(windows, new PrivateStore(store.Root)).Recover(); Need(Same(windows.Read(), prior), "real persisted WinINet recovery");
        }
        finally { windows.Write(original); }
        Need(Same(windows.Read(), original), "CI original proxy restored");
        Console.WriteLine("PASS: real WinINet per-connection PAC/proxy snapshot and recovery");
    }
    static async Task Native(string binary)
    {
        var hash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(binary)));
        Need(CoreHost.EmbeddedHash().Equals(hash, StringComparison.OrdinalIgnoreCase), "embedded core manifest matches packaged binary");
        int http = CoreHost.FreePort(), socks; do { socks = CoreHost.FreePort(); } while (http == socks);
        string config = JsonSerializer.Serialize(new { log = new { loglevel = "none" }, inbounds = new object[] {
            new { listen="127.0.0.1", port=http, protocol="http", settings=new {} },
            new { listen="127.0.0.1", port=socks, protocol="socks", settings=new {auth="noauth"} } }, outbounds=new [] {new {protocol="blackhole"}} });
        using (var core = new CoreHost(binary, hash))
        {
            await core.StartAsync(config, http, socks, CancellationToken.None); Need(core.Running, "native stdin config startup");
            var pid = core.ProcessId!.Value; core.Dispose();
            try { using var p = Process.GetProcessById(pid); Need(p.HasExited, "job killed core"); } catch (ArgumentException) { count++; }
        }
        using (var wrong = new CoreHost(binary, new string('0',64)))
        { try { await wrong.StartAsync(config,http,socks,CancellationToken.None); throw new Exception("hash mismatch accepted"); } catch (IOException) { count++; } }
        using (var cancelled = new CoreHost(binary,hash))
        { try { await cancelled.StartAsync(config,http,socks,new CancellationToken(true)); throw new Exception("cancel ignored"); } catch (OperationCanceledException) { count++; } Need(!cancelled.Running,"cancel left no child"); }
        using (var invalid = new CoreHost(binary,hash))
        { try { await invalid.StartAsync("{}",http,socks,CancellationToken.None); throw new Exception("invalid core ready"); } catch (Exception e) when (e is IOException or OperationCanceledException) { count++; } }
        Console.WriteLine("PASS: real Windows core stdin, readiness, hash rejection, cancellation and job cleanup");
    }
    static void WindowClose(string work)
    {
        var app = new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown };
        var unexpected = new List<string>();
        app.DispatcherUnhandledException += (_, e) => { unexpected.Add(e.Exception.GetType().Name); e.Handled = true; };
        using var watcher = Process.GetCurrentProcess();
        try
        {
            for (int mode = 0; mode < 3; mode++)
            {
                var settings = new Settings(); var before = settings.Read(); var journal = new Journal();
                var lease = new ProxyLease(settings, journal);
                if (mode != 0) lease.Apply(22080);
                if (mode == 2) settings.Partial = true; // Restore fails: keep journal but still close the window.
                var store = new PrivateStore(Path.Combine(work, "close-" + mode));
                var window = new MainWindow(store, lease, watcher);
                var frame = new DispatcherFrame(); bool closed = false;
                window.Closed += (_, _) => { closed = true; frame.Continue = false; };
                var deadline = new DispatcherTimer { Interval = TimeSpan.FromSeconds(5) };
                deadline.Tick += (_, _) => frame.Continue = false;
                window.Show(); deadline.Start(); window.Close();
                if (!closed) Dispatcher.PushFrame(frame);
                deadline.Stop();
                Need(closed, "single close request must close idle window");
                Need(unexpected.Count == 0, "no hidden reentrant WPF Close exception");
                if (mode < 2)
                {
                    Need(journal.Load() == null, "normal close clears restored journal");
                    Need(Same(settings.Read(), before), "normal close restores previous proxy");
                }
                else Need(journal.Load() != null, "failed restore leaves recoverable journal");
            }
        }
        finally { app.Shutdown(); }
        Console.WriteLine("PASS: single-request WPF close with synchronous stop, restored proxy and failed-restore journal");
    }
    [STAThread]
    static int Main(string[] args)
    {
        try
        {
            if (args.Length == 2 && args[0] == "--serve-fixture")
            {
                var p = JsonNode.Parse(File.ReadAllText(args[1]))!;
                var binary = Path.GetFullPath(p["binary"]!.GetValue<string>());
                var hash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(binary)));
                using var core = new CoreHost(binary, hash);
                core.StartAsync(File.ReadAllText(p["config"]!.GetValue<string>()), p["http"]!.GetValue<int>(),
                    p["socks"]!.GetValue<int>(), CancellationToken.None).GetAwaiter().GetResult();
                using var instance = new PrivateStore().Lock();
                var lease = new ProxyLease(new WindowsProxy(), new PrivateStore());
                lease.Recover();
                var before = new WindowsProxy().Read();
                File.WriteAllText(p["snapshot"]!.GetValue<string>(), JsonSerializer.Serialize(before));
                lease.Apply(p["http"]!.GetValue<int>());
                File.WriteAllText(p["ready"]!.GetValue<string>(), JsonSerializer.Serialize(new {
                    corePid = core.ProcessId!.Value, ownerTicks = Process.GetCurrentProcess().StartTime.ToUniversalTime().Ticks }));
                Console.ReadLine();
                lease.Recover();
                return 0;
            }
            if (args.Length == 2 && args[0] == "--check-proxy-snapshot")
            {
                var before = JsonSerializer.Deserialize<Dictionary<string, ProxyValue?>>(File.ReadAllText(args[1]))!;
                Need(Same(new WindowsProxy().Read(), before), "watchdog restored exact prior settings");
                Need(new PrivateStore().Load() == null, "watchdog removed recovery journal");
                Console.WriteLine("PASS: packaged recovery watchdog restored proxy after owner crash");
                return 0;
            }
            if (args.Length == 2 && args[0] == "--restore-proxy-snapshot")
            {
                var before = JsonSerializer.Deserialize<Dictionary<string, ProxyValue?>>(File.ReadAllText(args[1]))!;
                new WindowsProxy().Write(before); new PrivateStore().Delete(); return 0;
            }
            if (args.Length == 2 && args[0] == "--fixture-config")
            {
                var p = JsonNode.Parse(File.ReadAllText(args[1]))!;
                var parsed = S3Profile.Parse(p["link"]!.GetValue<string>());
                File.WriteAllText(p["output"]!.GetValue<string>(), parsed.CreateConfig(p["http"]!.GetValue<int>(), p["socks"]!.GetValue<int>()));
                return 0;
            }
            if (args.Length != 1) return 2;
            Unit(); var work = Path.Combine(Path.GetTempPath(), "rxpro-tests-" + Guid.NewGuid()); Directory.CreateDirectory(work);
            try { Storage(work); SystemProxy(work); Native(Path.GetFullPath(args[0])).GetAwaiter().GetResult(); WindowClose(work); }
            finally { Directory.Delete(work, true); }
            Console.WriteLine($"PASS: {count} assertions"); return 0;
        }
        catch (Exception e) { Console.Error.WriteLine("FAIL: " + e.GetType().Name + " / " + (e is ProfileException ? "profile rejected" : e.StackTrace)); return 1; }
    }
}
