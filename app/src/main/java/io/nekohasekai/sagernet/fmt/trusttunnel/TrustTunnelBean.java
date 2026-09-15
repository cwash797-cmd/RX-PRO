package io.nekohasekai.sagernet.fmt.trusttunnel;

import androidx.annotation.NonNull;
import com.esotericsoftware.kryo.io.ByteBufferInput;
import com.esotericsoftware.kryo.io.ByteBufferOutput;
import io.nekohasekai.sagernet.fmt.AbstractBean;
import io.nekohasekai.sagernet.fmt.KryoConverters;

/** RX-PRO TrustTunnel profile. Never log toString(): it intentionally omits credentials. */
public class TrustTunnelBean extends AbstractBean {
    public String hostname;
    public String sni;
    public String username;
    public String password;
    public String clientRandomPrefix;
    public String certificate;
    public String upstreamProtocol;
    public String dnsUpstreams;
    public String addresses;
    public Boolean hasIpv6;
    public Boolean skipVerification;
    public Boolean antiDpi;

    @Override public void initializeDefaultValues() {
        super.initializeDefaultValues();
        if (hostname == null || hostname.isEmpty()) hostname = serverAddress;
        if (sni == null) sni = "";
        if (username == null) username = "";
        if (password == null) password = "";
        if (clientRandomPrefix == null) clientRandomPrefix = "";
        if (certificate == null) certificate = "";
        if (upstreamProtocol == null) upstreamProtocol = "http2";
        if (dnsUpstreams == null) dnsUpstreams = "";
        if (addresses == null) addresses = "";
        if (hasIpv6 == null) hasIpv6 = true;
        if (skipVerification == null) skipVerification = false;
        if (antiDpi == null) antiDpi = false;
    }
    @Override public void serialize(ByteBufferOutput out) {
        out.writeInt(0); super.serialize(out);
        out.writeString(hostname); out.writeString(sni);
        out.writeString(username); out.writeString(password);
        out.writeString(clientRandomPrefix); out.writeString(certificate);
        out.writeString(upstreamProtocol); out.writeString(dnsUpstreams);
        out.writeString(addresses); out.writeBoolean(hasIpv6);
        out.writeBoolean(skipVerification); out.writeBoolean(antiDpi);
    }
    @Override public void deserialize(ByteBufferInput in) {
        int version = in.readInt();
        if (version != 0) throw new IllegalArgumentException("Unsupported TrustTunnel profile version");
        super.deserialize(in);
        hostname = in.readString(); sni = in.readString();
        username = in.readString(); password = in.readString();
        clientRandomPrefix = in.readString(); certificate = in.readString();
        upstreamProtocol = in.readString(); dnsUpstreams = in.readString();
        addresses = in.readString(); hasIpv6 = in.readBoolean();
        skipVerification = in.readBoolean(); antiDpi = in.readBoolean();
    }
    @NonNull @Override public TrustTunnelBean clone() {
        return KryoConverters.deserialize(new TrustTunnelBean(), KryoConverters.serialize(this));
    }
    @NonNull @Override public String toString() { return "TrustTunnelBean(redacted)"; }
    public static final Creator<TrustTunnelBean> CREATOR = new CREATOR<TrustTunnelBean>() {
        @NonNull @Override public TrustTunnelBean newInstance() { return new TrustTunnelBean(); }
        @Override public TrustTunnelBean[] newArray(int size) { return new TrustTunnelBean[size]; }
    };
}
