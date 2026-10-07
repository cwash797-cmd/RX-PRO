namespace RxPro.Core;

// Persist the before-image BEFORE touching settings. A crash at any write is recoverable.
public sealed record ProxyValue(string Kind, string Value);
public sealed record ProxyJournal(Dictionary<string, ProxyValue?> Before, Dictionary<string, ProxyValue?> Owned);
public interface IProxySettings
{
    Dictionary<string, ProxyValue?> Read();
    void Write(Dictionary<string, ProxyValue?> values);
}
public interface IProxyJournal
{
    ProxyJournal? Load();
    void Save(ProxyJournal state);
    void Delete();
}
public sealed class ProxyLease(IProxySettings settings, IProxyJournal journal)
{
    public bool Recover()
    {
        var saved = journal.Load(); if (saved is null) return false;
        var current = settings.Read();
        // Whole-set compare-and-swap. Never override settings changed by the user or another VPN.
        var ours = saved.Owned.All(p => current.TryGetValue(p.Key, out var v) &&
            (v == p.Value || v == saved.Before[p.Key]));
        if (ours)
        {
            settings.Write(saved.Before);
        }
        journal.Delete();
        return !ours;
    }
    public void Apply(int port)
    {
        if (port is < 1024 or > 65535) throw new ArgumentOutOfRangeException(nameof(port));
        if (journal.Load() is not null) throw new InvalidOperationException("Сначала восстановите прежний прокси.");
        var before = settings.Read();
        var owned = new Dictionary<string, ProxyValue?>(before) {
            ["Flags"] = new("DWord", "3"), // DIRECT | PROXY; temporarily suppress PAC and WPAD.
            ["ProxyServer"] = new("String", $"http=127.0.0.1:{port};https=127.0.0.1:{port}"),
            ["ProxyOverride"] = new("String", "localhost;127.*;[::1]"),
            ["AutoConfigURL"] = new("String", "")
        };
        journal.Save(new(before, owned));
        settings.Write(owned);
    }
}
