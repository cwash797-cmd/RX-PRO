package io.nekohasekai.sagernet.fmt.trusttunnel

import io.nekohasekai.sagernet.ktx.toStringPretty
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okio.ByteString.Companion.decodeBase64
import okio.ByteString.Companion.toByteString
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.security.cert.CertificateFactory

private const val MAX_LINK = 131072
private fun invalid(): Nothing = throw IllegalArgumentException("Invalid TrustTunnel link (credentials hidden)")
private fun utf8(bytes: ByteArray): String = try {
    Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
} catch (_: Exception) { invalid() }

private class TlvReader(val bytes: ByteArray) {
    var position = 0
    fun number(): Long {
        if (position >= bytes.size) invalid()
        val first = bytes[position++].toInt() and 255
        val size = 1 shl (first ushr 6)
        if (bytes.size - position < size - 1) invalid()
        var result = (first and 63).toLong()
        repeat(size - 1) { result = (result shl 8) or (bytes[position++].toLong() and 255) }
        return result
    }
    fun data(): ByteArray {
        val length = number()
        if (length > bytes.size - position) invalid()
        return bytes.copyOfRange(position, position + length.toInt()).also { position += length.toInt() }
    }
}
private fun number(bytes: ByteArray): Long {
    val r = TlvReader(bytes); val value = r.number()
    if (r.position != bytes.size) invalid()
    return value
}
private fun flag(bytes: ByteArray): Boolean {
    if (bytes.size != 1 || bytes[0].toInt() !in 0..1) invalid()
    return bytes[0].toInt() == 1
}
private fun addresses(bean: TrustTunnelBean, list: List<String>) {
    if (list.isEmpty() || list.size > 64) invalid()
    list.forEach { value ->
        val u = ("https://$value").toHttpUrlOrNull() ?: invalid()
        if (u.username.isNotEmpty() || u.password.isNotEmpty() || u.encodedPath != "/" || u.query != null || u.fragment != null) invalid()
    }
    val first = ("https://${list.first()}").toHttpUrlOrNull() ?: invalid()
    bean.serverAddress = first.host; bean.serverPort = first.port
    bean.addresses = list.joinToString("\n")
}

fun parseTrustTunnel(link: String): TrustTunnelBean {
    if (link.length > MAX_LINK || !link.startsWith("tt://", ignoreCase = true)) invalid()
    val bean = TrustTunnelBean()
    if (link.substring(5).startsWith("?")) {
        val encoded = link.substring(6).substringBefore('#')
        val payload = encoded.decodeBase64()?.toByteArray() ?: invalid()
        if (payload.size > MAX_LINK) invalid()
        val reader = TlvReader(payload)
        val values = linkedMapOf<Long, ByteArray>()
        val endpoints = mutableListOf<String>()
        while (reader.position < payload.size) {
            val tag = reader.number(); val value = reader.data()
            if (tag == 2L) endpoints.add(utf8(value)) else values[tag] = value
        }
        if (values[0]?.let(::number)?.let { it > 1 } == true) invalid()
        bean.hostname = utf8(values[1] ?: invalid())
        addresses(bean, endpoints)
        bean.username = utf8(values[5] ?: invalid())
        bean.password = utf8(values[6] ?: invalid())
        values[3]?.let { bean.sni = utf8(it) }
        values[4]?.let { bean.hasIpv6 = flag(it) }
        values[7]?.let { bean.skipVerification = flag(it) }
        values[8]?.let { der ->
            val certs = try { CertificateFactory.getInstance("X.509").generateCertificates(der.inputStream()) } catch (_: Exception) { invalid() }
            if (certs.isEmpty()) invalid()
            bean.certificate = certs.joinToString("\n") {
                "-----BEGIN CERTIFICATE-----\n" + it.encoded.toByteString().base64().chunked(64).joinToString("\n") + "\n-----END CERTIFICATE-----"
            }
        }
        values[9]?.let { bean.upstreamProtocol = when (number(it)) { 1L -> "http2"; 2L -> "http3"; else -> invalid() } }
        values[10]?.let { bean.antiDpi = flag(it) }
        values[11]?.let { bean.clientRandomPrefix = utf8(it) }
        values[12]?.let { bean.name = utf8(it) }
        values[13]?.let {
            val dns = TlvReader(it); val list = mutableListOf<String>()
            while (dns.position < it.size) list.add(utf8(dns.data()))
            bean.dnsUpstreams = list.joinToString("\n")
        }
    } else {
        val url = ("https://" + link.substring(5)).toHttpUrlOrNull() ?: invalid()
        bean.serverAddress = url.host; bean.serverPort = url.port
        bean.hostname = url.queryParameter("hostname")?.takeIf { it.isNotBlank() } ?: url.host
        bean.username = url.username; bean.password = url.password
        bean.sni = url.queryParameter("sni") ?: url.queryParameter("custom_sni") ?: ""
        bean.clientRandomPrefix = url.queryParameter("client_random_prefix") ?: url.queryParameter("client_random") ?: ""
        val security = url.queryParameter("security") ?: "tls"
        require(security == "tls") { "TrustTunnel requires TLS" }
        val protocol = url.queryParameter("upstream_protocol") ?: url.queryParameter("alpn") ?: "h2"
        bean.upstreamProtocol = when (protocol) { "h2", "http2" -> "http2"; "h3", "http3" -> "http3"; else -> invalid() }
        fun boolean(key: String, default: Boolean): Boolean = when (url.queryParameter(key)) {
            null -> default; "true", "1" -> true; "false", "0" -> false; else -> invalid()
        }
        bean.hasIpv6 = boolean("has_ipv6", true)
        bean.skipVerification = boolean("skip_verification", false)
        bean.antiDpi = boolean("anti_dpi", false)
        bean.dnsUpstreams = url.queryParameterValues("dns_upstream").filterNotNull().joinToString("\n")
        bean.name = url.fragment ?: ""
    }
    bean.initializeDefaultValues()
    if (bean.hostname.isBlank() || bean.username.isBlank() || bean.password.isBlank() || bean.username.contains(':')) invalid()
    if ((bean.hostname + bean.sni + bean.username + bean.password).any { it.code < 32 || it.code == 127 }) invalid()
    if (bean.clientRandomPrefix.isNotEmpty()) {
        val parts = bean.clientRandomPrefix.split('/')
        if (parts.size !in 1..2 || parts.any { it.isEmpty() || it.length > 64 || it.length % 2 != 0 || !it.matches(Regex("[0-9a-fA-F]+")) }) invalid()
        if (parts.size == 2 && parts[0].length != parts[1].length) invalid()
    }
    return bean
}

private fun ByteArrayOutputStream.varint(value: Int) {
    when { value < 64 -> write(value)
        value < 16384 -> { write(0x40 or (value ushr 8)); write(value and 255) }
        else -> { write(0x80 or (value ushr 24)); write((value ushr 16) and 255); write((value ushr 8) and 255); write(value and 255) }
    }
}
fun TrustTunnelBean.toUri(): String {
    require(upstreamProtocol in listOf("http2", "http3")) { "TrustTunnel protocol must be http2 or http3" }
    require(serverAddress.isNotBlank() && serverPort in 1..65535 && hostname.isNotBlank()) { "Invalid TrustTunnel address or TLS hostname" }
    val out = ByteArrayOutputStream()
    fun field(tag: Int, value: ByteArray) { out.varint(tag); out.varint(value.size); out.write(value) }
    fun text(tag: Int, value: String) { if (value.isNotEmpty()) field(tag, value.toByteArray(Charsets.UTF_8)) }
    field(0, byteArrayOf(1)); text(1, hostname)
    val server = if (serverAddress.contains(':')) "[$serverAddress]:$serverPort" else "$serverAddress:$serverPort"
    // The active address is first; retain the remaining imported endpoints for sharing.
    text(2, server)
    addresses.lines().filter { it.isNotBlank() && it != server }.forEach { text(2, it) }
    text(3, sni); field(4, byteArrayOf(if (hasIpv6) 1 else 0))
    text(5, username); text(6, password); field(7, byteArrayOf(if (skipVerification) 1 else 0))
    if (certificate.isNotBlank()) {
        val certs = CertificateFactory.getInstance("X.509").generateCertificates(certificate.byteInputStream())
        require(certs.isNotEmpty()) { "Invalid TrustTunnel certificate" }
        val der = ByteArrayOutputStream(); certs.forEach { der.write(it.encoded) }; field(8, der.toByteArray())
    }
    field(9, byteArrayOf(if (upstreamProtocol == "http3") 2 else 1))
    field(10, byteArrayOf(if (antiDpi) 1 else 0)); text(11, clientRandomPrefix); text(12, name)
    if (dnsUpstreams.isNotBlank()) {
        val data = ByteArrayOutputStream()
        dnsUpstreams.lines().filter { it.isNotBlank() }.forEach { val b = it.toByteArray(); data.varint(b.size); data.write(b) }
        field(13, data.toByteArray())
    }
    return "tt://?" + out.toByteArray().toByteString().base64Url().trimEnd('=')
}

fun TrustTunnelBean.buildTrustTunnelConfig(port: Int): String {
    require(upstreamProtocol == "http2") { "TrustTunnel TEST supports HTTP/2 only; HTTP/3 profile was preserved but cannot run yet." }
    require(!antiDpi) { "TrustTunnel anti_dpi flag is not supported in this TEST. client_random_prefix is supported." }
    dnsUpstreams.lines().filter { it.isNotBlank() }.forEach { value ->
        val raw = value.removePrefix("tcp://")
        val ip = raw.removeSurrounding("[", "]")
        val literal = com.google.common.net.InetAddresses.isInetAddress(ip)
        val url = ("https://$raw").toHttpUrlOrNull()
        val host = url?.host.orEmpty()
        val numericHost = com.google.common.net.InetAddresses.isInetAddress(host)
        require(literal || (url != null && numericHost && url.encodedPath == "/" && url.query == null && url.fragment == null && url.username.isEmpty() && url.password.isEmpty())) {
            "TrustTunnel TEST DNS supports IP or tcp://IP:port only; imported DNS was preserved."
        }
    }
    return JSONObject().apply {
        put("listen", "127.0.0.1:$port")
        put("server", if (finalAddress.contains(':')) "[$finalAddress]:$finalPort" else "$finalAddress:$finalPort")
        put("hostname", hostname)
        put("sni", sni.ifBlank { hostname })
        put("username", username); put("password", password)
        put("client_random_prefix", clientRandomPrefix)
        put("certificate", certificate)
        put("skip_verification", skipVerification)
        put("has_ipv6", hasIpv6)
        put("dns_upstreams", JSONArray(dnsUpstreams.lines().filter { it.isNotBlank() }))
    }.toStringPretty()
}
