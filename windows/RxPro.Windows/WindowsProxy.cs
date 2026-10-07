using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using RxPro.Core;

namespace RxPro.Windows;

// Use WinINet's supported per-connection API, NOT direct ProxyEnable registry edits:
// the latter miss PAC/WPAD flags cached in DefaultConnectionSettings.
public sealed class WindowsProxy : IProxySettings
{
    [StructLayout(LayoutKind.Sequential)] private struct Option { public int Id; public IntPtr Value; }
    [StructLayout(LayoutKind.Sequential)] private struct Options
    { public int Size; public IntPtr Connection; public int Count; public int Error; public IntPtr Items; }
    [DllImport("wininet.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool InternetQueryOptionW(IntPtr h, int option, ref Options buffer, ref int length);
    [DllImport("wininet.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool InternetSetOptionW(IntPtr h, int option, IntPtr buffer, int length);
    [DllImport("kernel32.dll")] private static extern IntPtr GlobalFree(IntPtr p);
    private static readonly string[] Names = ["Flags", "ProxyServer", "ProxyOverride", "AutoConfigURL"];
    public static void CheckPolicy()
    {
        foreach (var hive in new[] { Registry.CurrentUser, Registry.LocalMachine })
        {
            using var settings = hive.OpenSubKey(@"Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings");
            using var panel = hive.OpenSubKey(@"Software\Policies\Microsoft\Internet Explorer\Control Panel");
            if (settings?.GetValue("ProxySettingsPerUser") is int n && n == 0 ||
                panel?.GetValue("Proxy") is int p && p != 0)
                throw new IOException("Прокси управляется политикой организации. Используйте ручной режим.");
        }
    }
    public Dictionary<string, ProxyValue?> Read()
    {
        int size = Marshal.SizeOf<Option>(); var buffer = Marshal.AllocHGlobal(size * 4);
        var list = new Options { Size = Marshal.SizeOf<Options>(), Count = 4, Items = buffer };
        var output = new Dictionary<string, ProxyValue?>(); bool success = false;
        try
        {
            for (int i = 0; i < 4; i++) Marshal.StructureToPtr(new Option { Id = i + 1 }, buffer + size * i, false);
            int length = list.Size;
            if (!InternetQueryOptionW(IntPtr.Zero, 75, ref list, ref length)) throw new IOException("Не удалось прочитать системный прокси.");
            success = true;
            for (int i = 0; i < 4; i++)
            {
                var o = Marshal.PtrToStructure<Option>(buffer + size * i);
                output[Names[i]] = new(i == 0 ? "DWord" : "String", i == 0 ? o.Value.ToInt64().ToString() : Marshal.PtrToStringUni(o.Value) ?? "");
            }
            return output;
        }
        finally
        {
            if (success) for (int i = 1; i < 4; i++) GlobalFree(Marshal.PtrToStructure<Option>(buffer + size * i).Value);
            Marshal.FreeHGlobal(buffer);
        }
    }
    public void Write(Dictionary<string, ProxyValue?> values)
    {
        CheckPolicy();
        int size = Marshal.SizeOf<Option>(); var buffer = Marshal.AllocHGlobal(size * 4);
        var strings = new List<IntPtr>(); var listPointer = Marshal.AllocHGlobal(Marshal.SizeOf<Options>());
        try
        {
            for (int i = 0; i < 4; i++)
            {
                var v = values[Names[i]] ?? throw new IOException("Неполный снимок прокси.");
                IntPtr p;
                if (i == 0) p = new IntPtr(int.Parse(v.Value));
                else { p = Marshal.StringToHGlobalUni(v.Value); strings.Add(p); }
                Marshal.StructureToPtr(new Option { Id = i + 1, Value = p }, buffer + size * i, false);
            }
            var list = new Options { Size = Marshal.SizeOf<Options>(), Count = 4, Items = buffer };
            Marshal.StructureToPtr(list, listPointer, false);
            if (!InternetSetOptionW(IntPtr.Zero, 75, listPointer, list.Size)) throw new IOException("Не удалось изменить системный прокси.");
            _ = InternetSetOptionW(IntPtr.Zero, 39, IntPtr.Zero, 0);
            _ = InternetSetOptionW(IntPtr.Zero, 37, IntPtr.Zero, 0);
        }
        finally { foreach (var p in strings) Marshal.FreeHGlobal(p); Marshal.FreeHGlobal(buffer); Marshal.FreeHGlobal(listPointer); }
    }
}
