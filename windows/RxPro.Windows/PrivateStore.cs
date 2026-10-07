using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using RxPro.Core;

namespace RxPro.Windows;

public static class UserProtection
{
    [StructLayout(LayoutKind.Sequential)] private struct Blob { public int Size; public IntPtr Data; }
    [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CryptProtectData(ref Blob input, string? description, IntPtr entropy, IntPtr reserved, IntPtr prompt, int flags, out Blob output);
    [DllImport("crypt32.dll", SetLastError = true)]
    private static extern bool CryptUnprotectData(ref Blob input, IntPtr description, IntPtr entropy, IntPtr reserved, IntPtr prompt, int flags, out Blob output);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr memory);
    public static byte[] Transform(byte[] bytes, bool encrypt)
    {
        var input = new Blob { Size = bytes.Length, Data = Marshal.AllocHGlobal(bytes.Length) };
        Blob output = default;
        try
        {
            Marshal.Copy(bytes, 0, input.Data, bytes.Length);
            var ok = encrypt ? CryptProtectData(ref input, null, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out output)
                             : CryptUnprotectData(ref input, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out output);
            if (!ok) throw new IOException("Не удалось прочитать защищённые данные текущего пользователя Windows.");
            var result = new byte[output.Size]; Marshal.Copy(output.Data, result, 0, result.Length); return result;
        }
        finally
        {
            Marshal.Copy(new byte[bytes.Length], 0, input.Data, bytes.Length); Marshal.FreeHGlobal(input.Data);
            if (output.Data != IntPtr.Zero) { Marshal.Copy(new byte[output.Size], 0, output.Data, output.Size); LocalFree(output.Data); }
        }
    }
}
public sealed class SavedProfile
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Link { get; set; } = "";
    public override string ToString() => S3Profile.Parse(Link).Name;
}
public sealed class PrivateStore : IProxyJournal
{
    public string Root { get; }
    public static string DefaultRoot => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RX-PRO Windows");
    public PrivateStore(string? root = null)
    {
        Root = root ?? DefaultRoot;
        if (Directory.Exists(Root)) Check(Root);
        var directory = Directory.CreateDirectory(Root);
        var sid = WindowsIdentity.GetCurrent().User ?? throw new IOException("Нет Windows SID.");
        var acl = new DirectorySecurity(); acl.SetOwner(sid); acl.SetAccessRuleProtection(true, false);
        acl.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        directory.SetAccessControl(acl);
    }
    private static void Check(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new IOException("Ссылки файловой системы запрещены для приватных данных.");
    }
    public FileStream Lock()
    {
        var path = Path.Combine(Root, "instance.lock"); if (File.Exists(path)) Check(path);
        return new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
    }
    public T? Read<T>(string name)
    {
        var path = Path.Combine(Root, name); if (!File.Exists(path)) return default;
        Check(path); if (new FileInfo(path).Length > 1024 * 1024) throw new IOException("Файл данных слишком большой.");
        var plain = UserProtection.Transform(File.ReadAllBytes(path), false);
        try { return JsonSerializer.Deserialize<T>(plain) ?? throw new IOException("Пустой защищённый файл."); }
        finally { Array.Clear(plain); }
    }
    public void Write<T>(string name, T value)
    {
        var path = Path.Combine(Root, name); if (File.Exists(path)) Check(path);
        var plain = JsonSerializer.SerializeToUtf8Bytes(value); byte[] encrypted;
        try { encrypted = UserProtection.Transform(plain, true); } finally { Array.Clear(plain); }
        var temporary = Path.Combine(Root, Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            using (var file = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            { file.Write(encrypted); file.Flush(true); }
            File.Move(temporary, path, true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
    public List<SavedProfile> Profiles()
    {
        var values = Read<List<SavedProfile>>("profiles.dpapi") ?? [];
        if (values.Count > 100 || values.Select(p => p.Id).Distinct().Count() != values.Count) throw new IOException("Некорректный список профилей.");
        foreach (var p in values) { _ = S3Profile.Parse(p.Link); if (p.Id == Guid.Empty) throw new IOException("Некорректный ID."); }
        return values;
    }
    public ProxyJournal? Load() => Read<ProxyJournal>("proxy.dpapi");
    public void Save(ProxyJournal state) => Write("proxy.dpapi", state);
    public void Delete() => File.Delete(Path.Combine(Root, "proxy.dpapi"));
}
