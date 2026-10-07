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
class S3RegressionTest {
    private val encryption = "mlkem768x25519plus.native.1rtt.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    private fun storage() = JSONObject().put("version", 1).put("endpoint", "https://hb.ru-msk.vkcloud-storage.ru")
        .put("region", "ru-msk").put("bucket", "test-bucket").put("prefix", "probe-tests/data/android1")
        .put("accessKey", "CLIENT-FIXTURE").put("secretKey", "SECRET-FIXTURE")
    private fun link(data: JSONObject = storage()) = "vless://00000000-0000-4000-8000-000000000001@hb.ru-msk.vkcloud-storage.ru:443?type=xdrive&service=s3&encryption=$encryption&s3=" +
        URLEncoder.encode(data.toString().encodeUtf8().base64Url(), "UTF-8") + "#VK%20S3"

    @Test fun roundtripAndPersistence() {
        val bean = parseS3(link())
        val clone = bean.clone()
        assertTrue(clone.isS3)
        assertEquals("VK S3", clone.name)
        assertEquals(bean.s3Json, clone.s3Json)
        val restored = parseS3(clone.toUri())
        assertEquals(encryption, restored.vlessEncryption)
        assertEquals("CLIENT-FIXTURE", JSONObject(restored.s3Json).getString("accessKey"))
    }
    @Test fun transportUsesOnlyProtectedMapping() {
        val bean = parseS3(link()).apply { finalAddress = "127.0.0.1"; finalPort = 29001 }
        val result = JSONObject(bean.buildXrayConfig(29000, 1))
        assertEquals("warning", result.getJSONObject("log").getString("loglevel"))
        assertEquals(1, result.getJSONArray("outbounds").length())
        val outbound = result.getJSONArray("outbounds").getJSONObject(0)
        val stream = outbound.getJSONObject("streamSettings")
        assertEquals("xdrive", stream.getString("network"))
        assertEquals("127.0.0.1", stream.getString("address"))
        assertEquals(29001, stream.getInt("port"))
        val cfg = stream.getJSONObject("xdriveSettings")
        assertEquals("S3", cfg.getString("service"))
        val creds = JSONObject(cfg.getJSONArray("secrets").getString(0))
        assertEquals("https://hb.ru-msk.vkcloud-storage.ru", creds.getString("endpoint"))
        val users = outbound.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0).getJSONArray("users")
        assertEquals(encryption, users.getJSONObject(0).getString("encryption"))
    }
    @Test fun unmappedTransportCannotDialDirectly() {
        val bean = parseS3(link()).apply { finalAddress = serverAddress; finalPort = serverPort }
        assertThrows(IllegalArgumentException::class.java) { bean.buildXrayConfig(29000, 0) }
    }
    @Test fun rejectInsecureAndAmbiguousLinks() {
        for (bad in listOf(link().replace(encryption, "none"), link().replace(".1rtt.", ".0rtt."),
            link().replace("#VK%20S3", "&type=tcp"), link(storage().put("endpoint", "http://hb.ru-msk.vkcloud-storage.ru")),
            link(storage().put("prefix", "../other")), link(storage().put("endpoint", "https://evil.invalid")))) {
            assertThrows(IllegalArgumentException::class.java) { parseS3(bad) }
        }
    }
    @Test fun plainAndBase64Subscriptions() = runBlocking {
        for (text in listOf(link(), link().encodeUtf8().base64())) {
            val beans = RawUpdater.parseRaw(text)!!
            assertEquals(1, beans.size)
            assertTrue((beans.single() as XhttpBean).isS3)
        }
    }
    @Test fun accountsAtSameEndpointAreNotDeduplicated() {
        val one = parseS3(link())
        val two = parseS3(link(storage().put("prefix", "probe-tests/data/android2")))
        assertNotEquals(moe.matsuri.nb4a.Protocols.Deduplication(one, "VLESS-S3"),
            moe.matsuri.nb4a.Protocols.Deduplication(two, "VLESS-S3"))
    }
    @Test fun pastedLinksNeverBecomeVisibleNames() {
        for (name in listOf("S3-test-vless://fixture@localhost", "prefix-vless%3A%2F%2Fsecret",
            "s3=fixture-secret", "accessKey=fixture", "x".repeat(81))) {
            val bean = parseS3(link().substringBefore('#') + "#" + URLEncoder.encode(name, "UTF-8"))
            assertEquals("VK S3", bean.name)
            bean.name = name // Also cover existing beta1 records without rewriting the DB.
            assertEquals("VK S3", bean.displayName())
            assertEquals("VK S3", parseS3(bean.toUri()).name)
        }
        assertEquals("Мой VK", safeS3Name(" Мой VK "))
    }

    private fun policyFixture(forTest: Boolean = false): moe.matsuri.nb4a.SingBoxOptions.MyOptions {
        val bean = parseS3(link()).apply { finalAddress = LOCALHOST; finalPort = 29101 }
        val options = moe.matsuri.nb4a.SingBoxOptions.MyOptions().apply {
            inbounds = mutableListOf(
                moe.matsuri.nb4a.SingBoxOptions.Inbound_DirectOptions().apply {
                    type = "direct"; tag = "storage-mapping"; listen = LOCALHOST; listen_port = 29101
                    override_address = bean.serverAddress; override_port = 443
                },
                moe.matsuri.nb4a.SingBoxOptions.Inbound_MixedOptions().apply {
                    type = "mixed"; tag = "mixed-in"; listen = LOCALHOST; listen_port = 29102
                }
            )
            outbounds = mutableListOf(
                moe.matsuri.nb4a.SingBoxOptions.Outbound_SocksOptions().apply {
                    type = "socks"; tag = TAG_PROXY; server = LOCALHOST; server_port = 29103
                },
                moe.matsuri.nb4a.SingBoxOptions.Outbound().apply { type = "direct"; tag = "bypass" }
            )
        }
        applyS3Policy(options, bean, forTest)
        return options
    }

    @Test fun strictPolicyHasNoExternalDnsOrBypassAndPreservesTlsHost() {
        val options = policyFixture()
        val json = JSONObject(moe.matsuri.nb4a.utils.JavaUtil.gson.toJson(options.asMap()))
        val mapping = json.getJSONArray("inbounds").getJSONObject(0)
        assertEquals("95.163.53.117", mapping.getString("override_address"))
        assertEquals(443, mapping.getInt("override_port"))
        assertEquals("tcp", mapping.getString("network"))
        assertEquals(2, json.getJSONArray("outbounds").length())
        val direct = json.getJSONArray("outbounds").getJSONObject(1)
        assertEquals("s3-storage", direct.getString("tag"))
        assertFalse(direct.has("override_address")) // Destination is fixed at the only routed mapping inbound.
        val route = json.getJSONObject("route")
        assertEquals(TAG_PROXY, route.getString("final"))
        assertEquals("storage-mapping", route.getJSONArray("rules").getJSONObject(0).getJSONArray("inbound").getString(0))
        assertFalse(json.toString().contains("223.5.5.5"))
        assertFalse(json.toString().contains("dns-local"))
        val dns = json.getJSONObject("dns")
        val resolver = dns.getJSONArray("servers").getJSONObject(0)
        assertEquals("https://1.1.1.1/dns-query", resolver.getString("address"))
        assertEquals(TAG_PROXY, resolver.getString("detour"))
        val types = dns.getJSONArray("rules").getJSONObject(0).getJSONArray("query_type")
        assertEquals("[\"A\",\"AAAA\"]", types.toString())
        assertEquals("s3-dns", dns.getString("final")) // PTR does not enter fakeip.
        assertEquals("https://hb.ru-msk.vkcloud-storage.ru", storage().getString("endpoint"))
        java.io.File("build/s3-policy-vpn.json").apply { parentFile.mkdirs(); writeText(json.toString(2)) }
    }

    @Test fun urlTestAlsoUsesTunneledDnsWithoutFakeip() {
        val json = JSONObject(moe.matsuri.nb4a.utils.JavaUtil.gson.toJson(policyFixture(true).asMap()))
        val dns = json.getJSONObject("dns")
        assertFalse(dns.has("fakeip"))
        assertEquals(1, dns.getJSONArray("servers").length())
        assertEquals(TAG_PROXY, dns.getJSONArray("servers").getJSONObject(0).getString("detour"))
        java.io.File("build/s3-policy-test.json").apply { parentFile.mkdirs(); writeText(json.toString(2)) }
    }

    @Test fun unknownBootstrapHostFailsClosed() {
        assertEquals("95.163.53.117", s3BootstrapAddress("hb.vkcloud-storage.ru"))
        assertThrows(IllegalArgumentException::class.java) { s3BootstrapAddress("untrusted.invalid") }
    }

    @Test fun invalidMappingFailsClosed() {
        val options = policyFixture()
        val bean = parseS3(link()).apply { finalPort = 9999 }
        assertThrows(IllegalArgumentException::class.java) { applyS3Policy(options, bean, false) }
    }

}
