/******************************************************************************
 * RX-PRO: parse vless://...type=xhttp share links and build the Xray-core    *
 * client config used to run them through the bundled libxray.so binary.      *
 *                                                                            *
 * This program is free software: you can redistribute it and/or modify       *
 * it under the terms of the GNU General Public License as published by       *
 * the Free Software Foundation, either version 3 of the License, or          *
 *  (at your option) any later version.                                       *
 ******************************************************************************/

package io.nekohasekai.sagernet.fmt.xhttp

import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.fmt.LOCALHOST
import io.nekohasekai.sagernet.ktx.linkBuilder
import io.nekohasekai.sagernet.ktx.toLink
import io.nekohasekai.sagernet.ktx.toStringPretty
import io.nekohasekai.sagernet.ktx.urlSafe
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import org.json.JSONArray
import org.json.JSONObject

// vless://UUID@host:port?type=xhttp&mode=packet-up&path=/...&host=...&security=tls
//   &sni=...&fp=chrome&alpn=h2,http/1.1&allowInsecure=1&extra=%7B...%7D#name
// REALITY variant (v1.5.0): …&security=reality&pbk=<publicKey>&sid=<shortId>&spx=<spiderX>
fun parseXhttp(link: String): XhttpBean {
    val url = ("https://" + link.substringAfter("://")).toHttpUrlOrNull()
        ?: error("Invalid xhttp link: $link")
    return XhttpBean().apply {
        serverAddress = url.host
        serverPort = url.port
        uuid = url.username
        // ducksoft style: the path may also be encoded in the URL path segments
        if (url.pathSegments.size > 1 || url.pathSegments[0].isNotBlank()) {
            path = "/" + url.pathSegments.joinToString("/")
        }
        url.queryParameter("mode")?.takeIf { it.isNotBlank() }?.let { mode = it }
        url.queryParameter("path")?.takeIf { it.isNotBlank() }?.let { path = it }
        url.queryParameter("host")?.takeIf { it.isNotBlank() }?.let { host = it }
        url.queryParameter("extra")?.takeIf { it.isNotBlank() }?.let { extraJson = it }
        url.queryParameter("security")?.takeIf { it.isNotBlank() }?.let { security = it }
        url.queryParameter("sni")?.takeIf { it.isNotBlank() }?.let { sni = it }
        url.queryParameter("alpn")?.takeIf { it.isNotBlank() }?.let { alpn = it }
        url.queryParameter("fp")?.takeIf { it.isNotBlank() }?.let { fingerprint = it }
        url.queryParameter("allowInsecure")?.let { allowInsecure = it == "1" || it == "true" }
        // RX-PRO v1.5.0: REALITY params — previously silently DROPPED, which broke
        // every XHTTP+REALITY share link (profile imported but never connected).
        url.queryParameter("pbk")?.takeIf { it.isNotBlank() }?.let { realityPublicKey = it }
        url.queryParameter("sid")?.takeIf { it.isNotBlank() }?.let { realityShortId = it }
        url.queryParameter("spx")?.takeIf { it.isNotBlank() }?.let { realitySpiderX = it }
        // Some panels emit pbk/sid without security=reality — normalize.
        if (!realityPublicKey.isNullOrBlank() && security != "reality") security = "reality"
        // HttpUrl already percent-decodes the fragment
        name = url.fragment ?: ""
        // RX-PRO v1.5.1: some links carry mode/path/host ONLY inside the "extra"
        // JSON. Xray's SplitHTTPConfig.Build() UNCONDITIONALLY overwrites
        // extra.mode/path/host with the outer values — even when they're blank —
        // so a blank outer mode would silently reset e.g. "packet-up" to "auto"
        // and break servers that require a specific mode. Backfill from extra.
        if (!extraJson.isNullOrBlank()) {
            runCatching {
                val extra = JSONObject(extraJson)
                if (mode.isNullOrBlank() || mode == "auto") {
                    extra.optString("mode").takeIf { it.isNotBlank() }?.let { mode = it }
                }
                if (path.isNullOrBlank() || path == "/") {
                    extra.optString("path").takeIf { it.isNotBlank() }?.let { path = it }
                }
                if (host.isNullOrBlank()) {
                    extra.optString("host").takeIf { it.isNotBlank() }?.let { host = it }
                }
            }
        }
        initializeDefaultValues()
    }
}

fun XhttpBean.toUri(): String {
    val builder = linkBuilder().host(serverAddress).port(serverPort)
    if (uuid.isNotBlank()) builder.username(uuid)
    builder.addQueryParameter("type", "xhttp")
    builder.addQueryParameter("encryption", "none")
    builder.addQueryParameter("mode", mode)
    if (path.isNotBlank()) builder.addQueryParameter("path", path)
    if (host.isNotBlank()) builder.addQueryParameter("host", host)
    if (extraJson.isNotBlank()) builder.addQueryParameter("extra", extraJson)
    if (security.isNotBlank()) builder.addQueryParameter("security", security)
    if (sni.isNotBlank()) builder.addQueryParameter("sni", sni)
    if (alpn.isNotBlank()) builder.addQueryParameter("alpn", alpn)
    if (fingerprint.isNotBlank()) builder.addQueryParameter("fp", fingerprint)
    if (allowInsecure) builder.addQueryParameter("allowInsecure", "1")
    if (security == "reality") {
        if (realityPublicKey.isNotBlank()) builder.addQueryParameter("pbk", realityPublicKey)
        if (realityShortId.isNotBlank()) builder.addQueryParameter("sid", realityShortId)
        if (realitySpiderX.isNotBlank()) builder.addQueryParameter("spx", realitySpiderX)
    }
    if (name.isNotBlank()) builder.encodedFragment(name.urlSafe())
    return builder.toLink("vless")
}

// Xray client config: SOCKS inbound on 127.0.0.1:<port> -> VLESS outbound with
// xhttp transport (+ optional TLS).
//
// VPN loop prevention: like naive/mieru, sing-box creates a "direct" inbound that
// maps 127.0.0.1:<mappingPort> to the real server, and ConfigBuilder rewrites
// finalAddress/finalPort to that mapping. Xray therefore only ever talks to
// localhost and the real upstream socket is opened by sing-box through the
// protected fd — no traffic re-enters the tunnel.
fun XhttpBean.buildXrayConfig(port: Int): String {
    // RX-PRO v1.5.1: Xray's SplitHTTPConfig.Build() replaces the whole config
    // with "extra" when present, then FORCE-overwrites extra's mode/path/host
    // with the OUTER values — even blank ones. So the outer fields must always
    // carry the effective values or they'd wipe out what's inside extra.
    val extraObj: JSONObject? =
        if (extraJson.isNotBlank()) runCatching { JSONObject(extraJson) }.getOrNull() else null
    val effectiveMode = mode.ifBlank { extraObj?.optString("mode")?.ifBlank { null } ?: "auto" }
    val effectivePath = path.ifBlank { extraObj?.optString("path") ?: "" }
    val effectiveHost = host.ifBlank {
        extraObj?.optString("host")?.ifBlank { null } ?: sni.ifBlank { serverAddress }
    }

    val streamSettings = JSONObject().apply {
        put("network", "xhttp")
        put("xhttpSettings", JSONObject().apply {
            put("mode", effectiveMode)
            if (effectivePath.isNotBlank()) put("path", effectivePath)
            // the HTTP Host header must stay the real (camouflage) domain
            if (effectiveHost.isNotBlank()) put("host", effectiveHost)
            extraObj?.let { put("extra", it) }
        })
        if (security == "tls") {
            put("security", "tls")
            put("tlsSettings", JSONObject().apply {
                put("serverName", sni.ifBlank { host.ifBlank { serverAddress } })
                put("allowInsecure", allowInsecure)
                if (alpn.isNotBlank()) {
                    put(
                        "alpn",
                        JSONArray(alpn.split(",").map { it.trim() }.filter { it.isNotBlank() })
                    )
                }
                if (fingerprint.isNotBlank()) put("fingerprint", fingerprint)
            })
        }
        // RX-PRO v1.5.0: REALITY support — XHTTP servers are commonly deployed
        // behind REALITY; without realitySettings the outbound never connects.
        if (security == "reality") {
            put("security", "reality")
            put("realitySettings", JSONObject().apply {
                put("serverName", sni.ifBlank { host.ifBlank { serverAddress } })
                put("publicKey", realityPublicKey)
                if (realityShortId.isNotBlank()) put("shortId", realityShortId)
                if (realitySpiderX.isNotBlank()) put("spiderX", realitySpiderX)
                // Xray requires an explicit uTLS fingerprint with REALITY
                put("fingerprint", fingerprint.ifBlank { "chrome" })
            })
        }
    }

    return JSONObject().apply {
        put("log", JSONObject().apply {
            put("loglevel", if (DataStore.logLevel > 0) "debug" else "warning")
        })
        put("inbounds", JSONArray().apply {
            put(JSONObject().apply {
                put("tag", "socks-in")
                put("listen", LOCALHOST)
                put("port", port)
                put("protocol", "socks")
                put("settings", JSONObject().apply {
                    put("auth", "noauth")
                    put("udp", true)
                })
            })
        })
        put("outbounds", JSONArray().apply {
            put(JSONObject().apply {
                put("tag", "proxy")
                put("protocol", "vless")
                put("settings", JSONObject().apply {
                    put("vnext", JSONArray().apply {
                        put(JSONObject().apply {
                            put("address", finalAddress)
                            put("port", finalPort)
                            put("users", JSONArray().apply {
                                put(JSONObject().apply {
                                    put("id", uuid)
                                    put("encryption", "none")
                                    put("level", 0)
                                })
                            })
                        })
                    })
                })
                put("streamSettings", streamSettings)
            })
        })
    }.toStringPretty()
}
