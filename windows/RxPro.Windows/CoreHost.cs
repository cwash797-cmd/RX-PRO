using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace RxPro.Windows;

public sealed class KillJob : SafeHandleZeroOrMinusOneIsInvalid
{
    [StructLayout(LayoutKind.Sequential)] private struct Basic
    { public long ProcessTime, JobTime; public uint Flags; public UIntPtr Minimum, Maximum; public uint Active; public UIntPtr Affinity; public uint Priority, Scheduling; }
    [StructLayout(LayoutKind.Sequential)] private struct Io { public ulong A, B, C, D, E, F; }
    [StructLayout(LayoutKind.Sequential)] private struct Extended
    { public Basic Basic; public Io Io; public UIntPtr ProcessMemory, JobMemory, PeakProcess, PeakJob; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] private static extern IntPtr CreateJobObjectW(IntPtr attributes, string? name);
    [DllImport("kernel32.dll")] private static extern bool SetInformationJobObject(IntPtr job, int type, ref Extended data, uint length);
    [DllImport("kernel32.dll")] private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
    public KillJob() : base(true)
    {
        SetHandle(CreateJobObjectW(IntPtr.Zero, null));
        var info = new Extended { Basic = new Basic { Flags = 0x2000 } }; // KILL_ON_JOB_CLOSE
        if (IsInvalid || !SetInformationJobObject(handle, 9, ref info, (uint)Marshal.SizeOf<Extended>()))
        { Dispose(); throw new IOException("Не удалось создать изолированный процесс ядра."); }
    }
    public void Attach(Process process)
    {
        if (!AssignProcessToJobObject(handle, process.Handle)) throw new IOException("Не удалось ограничить время жизни ядра.");
    }
    protected override bool ReleaseHandle() => CloseHandle(handle);
}

public sealed class CoreHost(string binary, string expectedHash) : IDisposable
{
    private Process? process;
    private KillJob? job;
    public bool Running => process is { HasExited: false };
    public int? ProcessId => process?.Id;
    public static string EmbeddedHash()
    {
        using var resource = typeof(CoreHost).Assembly.GetManifestResourceStream("CoreHash") ?? throw new IOException("Нет manifest ядра.");
        return new StreamReader(resource).ReadToEnd().Trim();
    }
    public static int FreePort()
    {
        var socket = new TcpListener(IPAddress.Loopback, 0); socket.Start();
        try { return ((IPEndPoint)socket.LocalEndpoint).Port; } finally { socket.Stop(); }
    }
    public async Task StartAsync(string configuration, int httpPort, int socksPort, CancellationToken cancellation)
    {
        if (process != null) throw new IOException("Ядро уже запущено.");
        if (!File.Exists(binary) || (File.GetAttributes(binary) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Нет проверенного ядра. Распакуйте полный ZIP выпуска.");
        using (var file = File.OpenRead(binary))
            if (!Convert.ToHexString(SHA256.HashData(file)).Equals(expectedHash, StringComparison.OrdinalIgnoreCase))
                throw new IOException("Контрольная сумма ядра не совпадает. Подмена ядра запрещена.");
        try
        {
            cancellation.ThrowIfCancellationRequested(); job = new KillJob();
            var start = new ProcessStartInfo(binary) { UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true,
                StandardInputEncoding = new UTF8Encoding(false), WorkingDirectory = Path.GetDirectoryName(binary)! };
            foreach (var arg in new[] { "run", "-format", "json", "-config", "stdin:" }) start.ArgumentList.Add(arg);
            // Do not inherit implicit proxies, TLS trust overrides or diagnostics from the launching shell.
            foreach (var name in new[] { "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy", "SSL_CERT_FILE", "SSL_CERT_DIR", "XRAY_LOCATION_CONFIG", "XRAY_LOCATION_CONFDIR" }) start.Environment.Remove(name);
            start.Environment["GOMEMLIMIT"] = "192MiB";
            process = Process.Start(start) ?? throw new IOException("Ядро не запущено.");
            job.Attach(process);
            _ = Discard(process.StandardOutput); _ = Discard(process.StandardError);
            // Credentials travel only over a private pipe, never argv, environment or plaintext files.
            await process.StandardInput.WriteAsync(configuration.AsMemory(), cancellation);
            process.StandardInput.Close();
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation); timeout.CancelAfter(TimeSpan.FromSeconds(20));
            while (true)
            {
                timeout.Token.ThrowIfCancellationRequested();
                if (process.HasExited) throw new IOException("Ядро отклонило конфигурацию или порты заняты.");
                try
                {
                    using var socks = new TcpClient(AddressFamily.InterNetwork);
                    await socks.ConnectAsync(IPAddress.Loopback, socksPort, timeout.Token);
                    await socks.GetStream().WriteAsync(new byte[] { 5, 1, 0 }, timeout.Token);
                    var reply = new byte[2]; await socks.GetStream().ReadExactlyAsync(reply, timeout.Token);
                    if (reply[0] != 5 || reply[1] != 0) throw new IOException("Неверный SOCKS listener.");
                    using var http = new TcpClient(AddressFamily.InterNetwork);
                    await http.ConnectAsync(IPAddress.Loopback, httpPort, timeout.Token);
                    await Task.Delay(150, timeout.Token);
                    if (process.HasExited) throw new IOException("Ядро завершилось при запуске.");
                    return;
                }
                catch (SocketException) { await Task.Delay(80, timeout.Token); }
            }
        }
        catch { Dispose(); throw; }
    }
    private static async Task Discard(StreamReader reader)
    {
        var buffer = new char[2048];
        try { while (await reader.ReadAsync(buffer) != 0) { Array.Clear(buffer); } } catch { }
    }
    public void Dispose()
    {
        job?.Dispose(); job = null;
        if (process != null)
        {
            try { if (!process.HasExited) { process.Kill(true); process.WaitForExit(3000); } } catch { }
            process.Dispose(); process = null;
        }
    }
}
