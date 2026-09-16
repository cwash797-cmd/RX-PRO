package io.nekohasekai.sagernet.fmt

import android.app.Application
import io.nekohasekai.sagernet.database.*
import moe.matsuri.nb4a.SingBoxOptions
import moe.matsuri.nb4a.generateRuleSet
import moe.matsuri.nb4a.makeSingBoxRule
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28], application = Application::class)
class RouteRegressionTest {
    @Test fun newPresetsUseValidRuCategoryAndKeepPlayStoreDomains() {
        val presets = ruRoutePresets()
        assertEquals(3, presets.size)
        assertEquals("для RU", presets[0].name)
        assertEquals("googleapis.cn", presets[0].domains)
        assertEquals(0L, presets[0].outbound)
        assertEquals("geosite:category-ru", presets[1].domains)
        assertEquals("geoip:ru", presets[2].ip)
        assertTrue(presets.none { it.enabled })
        assertTrue(presets.none { it.domains == "geosite:cn" || it.domains == "geosite:ir" })
    }
    @Test fun legacyRuTagLoadsCategoryWithoutBreakingDnsOrRouteReferences() {
        val dns = SingBoxOptions.DNSRule_DefaultOptions().apply { makeSingBoxRule(listOf("geosite:ru")) }
        val route = SingBoxOptions.Rule_DefaultOptions().apply { makeSingBoxRule(listOf("geosite:ru"), false) }
        val sets = mutableListOf<SingBoxOptions.RuleSet>()
        generateRuleSet(route.rule_set, sets)
        assertEquals("geosite:ru", dns.rule_set.single())
        assertEquals("geosite:ru", sets.single().tag)
        assertEquals("geosite:category-ru", sets.single().path)
    }
    @Test fun otherGeoCodesAndGeoipAreUnchanged() {
        val sets = mutableListOf<SingBoxOptions.RuleSet>()
        generateRuleSet(listOf("geoip:ru", "geosite:category-ru", "geosite:yandex", "geosite:cn"), sets)
        assertTrue(sets.all { it.tag == it.path })
    }
    @Test fun allLocalizedDefaultCountryRulesMigrateIdempotently() {
        val templates = legacyRoutePresetChanges(RuntimeEnvironment.getApplication())
        assertTrue(templates.isNotEmpty())
        for ((old, replacement) in templates) {
            val saved = old.copy(id = 42, userOrder = 7, enabled = true)
            val changed = migrateLegacyRoutePreset(saved, templates)
            if (replacement == null) {
                assertNull(changed)
            } else {
                assertNotNull(changed)
                assertEquals(42L, changed!!.id)
                assertEquals(7L, changed.userOrder)
                assertTrue(changed.enabled)
                assertEquals(replacement.name, changed.name)
                assertEquals(replacement.domains, changed.domains)
                assertEquals(replacement.ip, changed.ip)
                assertEquals(saved.outbound, changed.outbound)
                assertEquals(changed, migrateLegacyRoutePreset(changed, templates))
            }
        }
    }
    @Test fun customizedRulesAreNeverDeletedOrRewritten() {
        val templates = legacyRoutePresetChanges(RuntimeEnvironment.getApplication())
        for ((old, _) in templates) {
            for (custom in listOf(old.copy(name = "My custom rule"), old.copy(port = "443"),
                old.copy(config = "{}"), old.copy(packages = setOf("example.app")),
                old.copy(domains = old.domains + "\nexample.com"), old.copy(outbound = 99))) {
                assertEquals(custom, migrateLegacyRoutePreset(custom, templates))
            }
        }
    }
}
