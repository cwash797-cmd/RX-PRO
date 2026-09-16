package io.nekohasekai.sagernet.fmt

import android.app.Application
import io.nekohasekai.sagernet.fmt.trusttunnel.TrustTunnelTest
import io.nekohasekai.sagernet.fmt.xhttp.*
import io.nekohasekai.sagernet.group.RawUpdater
import kotlinx.coroutines.runBlocking
import okio.ByteString.Companion.encodeUtf8
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.net.URLEncoder

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28], application = Application::class, shadows = [TrustTunnelTest.NativeLogShadow::class, TrustTunnelTest.AndroidSocketReflectionShadow::class])
class XhttpRegressionTest {
    private val base = "vless://00000000-0000-4000-8000-000000000001@x.example.com:443?type=xhttp&security=tls&sni=cert.example.com"
    private fun encoded(s: String) = URLEncoder.encode(s, "UTF-8")
    private val knobs = """{"mode":"packet-up","path":"/fixture","host":"http.example.com","xPaddingBytes":"100-200","noGRPCHeader":true,"xmux":{"maxConcurrency":"8-16","hKeepAlivePeriod":20}}"""

    @Test fun base64ExtraIsDecodedAndBackfilled() {
        for (extra in listOf(knobs, knobs.encodeUtf8().base64Url().trimEnd('='), knobs.encodeUtf8().base64())) {
            val b = parseXhttp(base + "&extra=" + encoded(extra))
            assertEquals("packet-up", b.mode)
            assertEquals("/fixture", b.path)
            assertEquals("http.example.com", b.host)
            assertEquals(20, JSONObject(b.extraJson).getJSONObject("xmux").getInt("hKeepAlivePeriod"))
        }
    }
    @Test fun explicitOuterDefaultsAreNotOverwritten() {
        val b = parseXhttp(base + "&mode=auto&path=%2F&extra=" + encoded(knobs))
        assertEquals("auto", b.mode)
        assertEquals("/", b.path)
    }
    @Test fun panel114SnakeCaseKnobsSurviveSubscriptionImport() {
        val j = JSONObject("""{"outbounds":[{"type":"vless","tag":"fixture","server":"x.example.com","server_port":443,"uuid":"00000000-0000-4000-8000-000000000001","tls":{"enabled":true,"server_name":"cert.example.com","utls":{"enabled":true,"fingerprint":"chrome"}},"transport":{"type":"xhttp","mode":"packet-up","path":"/fixture","host":"http.example.com","x_padding_bytes":"100-200","no_grpc_header":true,"sc_max_each_post_bytes":1000000,"xmux":{"max_concurrency":"8-16","h_keep_alive_period":20}}}]}""")
        val b = RawUpdater.parseJSON(j).single() as XhttpBean
        val extra = JSONObject(b.extraJson)
        assertEquals("100-200", extra.getString("xPaddingBytes"))
        assertTrue(extra.getBoolean("noGRPCHeader"))
        assertEquals(1000000, extra.getInt("scMaxEachPostBytes"))
        assertEquals("8-16", extra.getJSONObject("xmux").getString("maxConcurrency"))
        assertEquals(20, extra.getJSONObject("xmux").getInt("hKeepAlivePeriod"))
        assertFalse(extra.has("x_padding_bytes"))
        assertEquals("chrome", b.fingerprint)
        assertEquals("cert.example.com", b.sni)
        assertFalse(b.allowInsecure)
    }
    @Test fun invalidExtraMustNotSilentlyBecomeDefaultTransport() {
        val error = assertThrows(IllegalArgumentException::class.java) {
            parseXhttp(base + "&extra=PRIVATE-INVALID-FIXTURE")
        }
        assertFalse(error.message.orEmpty().contains("PRIVATE-INVALID-FIXTURE"))
    }
    @Test fun mappedConfigRetainsTlsAndHttpIdentity() {
        val b = parseXhttp(base + "&extra=" + encoded(knobs))
        b.finalAddress = "127.0.0.1"; b.finalPort = 25081
        val j = JSONObject(b.buildXrayConfig(25080, 0))
        val outbound = j.getJSONArray("outbounds").getJSONObject(0)
        val target = outbound.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0)
        assertEquals("127.0.0.1", target.getString("address"))
        assertEquals(25081, target.getInt("port"))
        val stream = outbound.getJSONObject("streamSettings")
        assertEquals("http.example.com", stream.getJSONObject("xhttpSettings").getString("host"))
        assertEquals("cert.example.com", stream.getJSONObject("tlsSettings").getString("serverName"))
        assertFalse(stream.getJSONObject("tlsSettings").getBoolean("allowInsecure"))
        assertTrue(stream.getJSONObject("xhttpSettings").getJSONObject("extra").has("xmux"))
    }
    @Test fun xrayContainerPreservesFlattenedAndNestedExtra() {
        val j = JSONObject("""{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"x.example.com","port":443,"users":[{"id":"00000000-0000-4000-8000-000000000001"}]}]},"streamSettings":{"network":"splithttp","security":"reality","realitySettings":{"publicKey":"fixture-public-key","shortId":"abcd","serverName":"cert.example.com","fingerprint":"chrome"},"splithttpSettings":{"xPaddingBytes":"10-20","extra":{"mode":"packet-up","path":"/nested","xPaddingBytes":"100-200","headers":{"X-Fixture":"unchanged_value"}}}}}]}""")
        val b = RawUpdater.parseJSON(j).single() as XhttpBean
        assertEquals("packet-up", b.mode)
        assertEquals("/nested", b.path)
        assertEquals("100-200", JSONObject(b.extraJson).getString("xPaddingBytes"))
        assertEquals("unchanged_value", JSONObject(b.extraJson).getJSONObject("headers").getString("X-Fixture"))
        val stream = JSONObject(b.buildXrayConfig(25080, 0)).getJSONArray("outbounds").getJSONObject(0).getJSONObject("streamSettings")
        assertEquals("fixture-public-key", stream.getJSONObject("realitySettings").getString("publicKey"))
        assertEquals("abcd", stream.getJSONObject("realitySettings").getString("shortId"))
    }
    @Test fun standaloneJsonRespectsDisabledTls() {
        val b = RawUpdater.parseJSON(JSONObject("""{"type":"vless","server":"x.example.com","server_port":80,"uuid":"00000000-0000-4000-8000-000000000001","tls":{"enabled":false},"transport":{"type":"xhttp","mode":"packet-up","x_padding_bytes":"100-200"}}""")).single() as XhttpBean
        assertEquals("none", b.security)
        assertEquals("100-200", JSONObject(b.extraJson).getString("xPaddingBytes"))
    }
    @Test fun separateDownloadEndpointIsPreservedButCannotBypassVpnProtection() {
        val b = parseXhttp(base + "&extra=" + encoded("""{"downloadSettings":{"address":"download.example.com","port":443}}"""))
        assertEquals("download.example.com", JSONObject(parseXhttp(b.toUri()).extraJson).getJSONObject("downloadSettings").getString("address"))
        val error = assertThrows(IllegalArgumentException::class.java) { b.buildXrayConfig(25080, 0) }
        assertFalse(error.message.orEmpty().contains("download.example.com"))
        assertTrue(error.message.orEmpty().contains("protected endpoint"))
    }
    @Test fun nativeLoopbackFixtureUsesProductionBuilder() {
        val b = parseXhttp(base + "&extra=" + encoded(knobs))
        b.security = "none"
        b.finalAddress = "127.0.0.1"; b.finalPort = 25081
        val config = b.buildXrayConfig(25080, 0)
        val dir = java.io.File("build/test-fixtures").apply { mkdirs() }
        java.io.File(dir, "xray-client.json").writeText(config)
        assertEquals("warning", JSONObject(config).getJSONObject("log").getString("loglevel"))
    }
    @Test fun plainAndBase64SubscriptionRoundtrip() = runBlocking {
        val link = base.replace("type=xhttp", "type=splithttp") + "&extra=" + encoded(knobs)
        for (text in listOf(link, link.encodeUtf8().base64())) {
            val b = RawUpdater.parseRaw(text)!!.single() as XhttpBean
            val restored = parseXhttp(b.toUri())
            assertEquals(b.mode, restored.mode)
            assertEquals(b.path, restored.path)
            assertEquals(b.extraJson, restored.extraJson)
        }
    }
}
