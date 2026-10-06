/******************************************************************************
 * RX-PRO: VLESS XHTTP profile, executed through the bundled Xray-core        *
 * binary (libxray.so). sing-box has no XHTTP transport, so these profiles    *
 * run as an external plugin process, same as naive/mieru.                    *
 *                                                                            *
 * This program is free software: you can redistribute it and/or modify      *
 * it under the terms of the GNU General Public License as published by      *
 * the Free Software Foundation, either version 3 of the License, or         *
 *  (at your option) any later version.                                      *
 ******************************************************************************/

package io.nekohasekai.sagernet.fmt.xhttp;

import androidx.annotation.NonNull;

import com.esotericsoftware.kryo.io.ByteBufferInput;
import com.esotericsoftware.kryo.io.ByteBufferOutput;

import org.jetbrains.annotations.NotNull;

import io.nekohasekai.sagernet.fmt.AbstractBean;
import io.nekohasekai.sagernet.fmt.KryoConverters;

public class XhttpBean extends AbstractBean {

    public String uuid;
    // Version 2: optional native S3 profile; old XHTTP records remain readable.
    public String s3Json;
    public String vlessEncryption;
    // xhttp transport
    public String mode;      // auto / packet-up / stream-up / stream-one
    public String path;
    public String host;
    // raw "extra" JSON from the share link (padding/xmux tuning), passed to Xray verbatim
    public String extraJson;
    // TLS / REALITY
    public String security;  // tls / reality / none
    public String sni;
    public String alpn;      // comma separated, e.g. "h2,http/1.1"
    public String fingerprint;
    public Boolean allowInsecure;
    // RX-PRO v1.5.0: REALITY params (security=reality&pbk=...&sid=...&spx=...)
    public String realityPublicKey;
    public String realityShortId;
    public String realitySpiderX;

    @Override
    public String displayName() {
        return s3Json != null && !s3Json.isEmpty() ? S3FmtKt.safeS3Name(name) : super.displayName();
    }

    @Override
    public void initializeDefaultValues() {
        super.initializeDefaultValues();
        if (uuid == null) uuid = "";
        if (s3Json == null) s3Json = "";
        if (vlessEncryption == null) vlessEncryption = "";
        if (mode == null) mode = "auto";
        if (path == null) path = "/";
        if (host == null) host = "";
        if (extraJson == null) extraJson = "";
        if (security == null) security = "tls";
        if (sni == null) sni = "";
        if (alpn == null) alpn = "";
        if (fingerprint == null) fingerprint = "";
        if (allowInsecure == null) allowInsecure = false;
        if (realityPublicKey == null) realityPublicKey = "";
        if (realityShortId == null) realityShortId = "";
        if (realitySpiderX == null) realitySpiderX = "";
    }

    @Override
    public void serialize(ByteBufferOutput output) {
        output.writeInt(2);
        super.serialize(output);
        output.writeString(uuid);
        output.writeString(mode);
        output.writeString(path);
        output.writeString(host);
        output.writeString(extraJson);
        output.writeString(security);
        output.writeString(sni);
        output.writeString(alpn);
        output.writeString(fingerprint);
        output.writeBoolean(allowInsecure);
        // version 1
        output.writeString(realityPublicKey);
        output.writeString(realityShortId);
        output.writeString(realitySpiderX);
        output.writeString(s3Json);
        output.writeString(vlessEncryption);
    }

    @Override
    public void deserialize(ByteBufferInput input) {
        int version = input.readInt();
        super.deserialize(input);
        uuid = input.readString();
        mode = input.readString();
        path = input.readString();
        host = input.readString();
        extraJson = input.readString();
        security = input.readString();
        sni = input.readString();
        alpn = input.readString();
        fingerprint = input.readString();
        allowInsecure = input.readBoolean();
        if (version >= 1) {
            realityPublicKey = input.readString();
            realityShortId = input.readString();
            realitySpiderX = input.readString();
        }
        if (version >= 2) {
            s3Json = input.readString();
            vlessEncryption = input.readString();
        }
    }

    @NotNull
    @Override
    public XhttpBean clone() {
        return KryoConverters.deserialize(new XhttpBean(), KryoConverters.serialize(this));
    }

    public static final Creator<XhttpBean> CREATOR = new CREATOR<XhttpBean>() {
        @NonNull
        @Override
        public XhttpBean newInstance() {
            return new XhttpBean();
        }

        @Override
        public XhttpBean[] newArray(int size) {
            return new XhttpBean[size];
        }
    };
}