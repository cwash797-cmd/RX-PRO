package io.nekohasekai.sagernet.database

import android.database.sqlite.SQLiteCantOpenDatabaseException
import android.content.Context
import android.content.res.Configuration
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.aidl.TrafficData
import io.nekohasekai.sagernet.fmt.AbstractBean
import io.nekohasekai.sagernet.ktx.Logs
import io.nekohasekai.sagernet.ktx.app
import io.nekohasekai.sagernet.ktx.applyDefaultValues
import java.io.IOException
import java.sql.SQLException
import java.util.*


object ProfileManager {

    interface Listener {
        suspend fun onAdd(profile: ProxyEntity)
        suspend fun onUpdated(data: TrafficData)
        suspend fun onUpdated(profile: ProxyEntity, noTraffic: Boolean)
        suspend fun onRemoved(groupId: Long, profileId: Long)
    }

    interface RuleListener {
        suspend fun onAdd(rule: RuleEntity)
        suspend fun onUpdated(rule: RuleEntity)
        suspend fun onRemoved(ruleId: Long)
        suspend fun onCleared()
    }

    private val listeners = ArrayList<Listener>()
    private val ruleListeners = ArrayList<RuleListener>()

    suspend fun iterator(what: suspend Listener.() -> Unit) {
        synchronized(listeners) {
            listeners.toList()
        }.forEach { listener ->
            what(listener)
        }
    }

    suspend fun ruleIterator(what: suspend RuleListener.() -> Unit) {
        val ruleListeners = synchronized(ruleListeners) {
            ruleListeners.toList()
        }
        for (listener in ruleListeners) {
            what(listener)
        }
    }

    fun addListener(listener: Listener) {
        synchronized(listeners) {
            listeners.add(listener)
        }
    }

    fun removeListener(listener: Listener) {
        synchronized(listeners) {
            listeners.remove(listener)
        }
    }

    fun addListener(listener: RuleListener) {
        synchronized(ruleListeners) {
            ruleListeners.add(listener)
        }
    }

    fun removeListener(listener: RuleListener) {
        synchronized(ruleListeners) {
            ruleListeners.remove(listener)
        }
    }

    suspend fun createProfile(groupId: Long, bean: AbstractBean): ProxyEntity {
        bean.applyDefaultValues()

        val profile = ProxyEntity(groupId = groupId).apply {
            id = 0
            putBean(bean)
            userOrder = SagerDatabase.proxyDao.nextOrder(groupId) ?: 1
        }
        profile.id = SagerDatabase.proxyDao.addProxy(profile)
        iterator { onAdd(profile) }
        return profile
    }

    suspend fun updateProfile(profile: ProxyEntity) {
        SagerDatabase.proxyDao.updateProxy(profile)
        iterator { onUpdated(profile, false) }
    }

    suspend fun updateProfile(profiles: List<ProxyEntity>) {
        SagerDatabase.proxyDao.updateProxy(profiles)
        profiles.forEach {
            iterator { onUpdated(it, false) }
        }
    }

    suspend fun deleteProfile2(groupId: Long, profileId: Long) {
        if (SagerDatabase.proxyDao.deleteById(profileId) == 0) return
        if (DataStore.selectedProxy == profileId) {
            DataStore.selectedProxy = 0L
        }
    }

    suspend fun deleteProfile(groupId: Long, profileId: Long) {
        if (SagerDatabase.proxyDao.deleteById(profileId) == 0) return
        if (DataStore.selectedProxy == profileId) {
            DataStore.selectedProxy = 0L
        }
        iterator { onRemoved(groupId, profileId) }
        if (SagerDatabase.proxyDao.countByGroup(groupId) > 1) {
            GroupManager.rearrange(groupId)
        }
    }

    fun getProfile(profileId: Long): ProxyEntity? {
        if (profileId == 0L) return null
        return try {
            SagerDatabase.proxyDao.getById(profileId)
        } catch (ex: SQLiteCantOpenDatabaseException) {
            throw IOException(ex)
        } catch (ex: SQLException) {
            Logs.w(ex)
            null
        }
    }

    fun getProfiles(profileIds: List<Long>): List<ProxyEntity> {
        if (profileIds.isEmpty()) return listOf()
        return try {
            SagerDatabase.proxyDao.getEntities(profileIds)
        } catch (ex: SQLiteCantOpenDatabaseException) {
            throw IOException(ex)
        } catch (ex: SQLException) {
            Logs.w(ex)
            listOf()
        }
    }

    // postUpdate: post to listeners, don't change the DB

    suspend fun postUpdate(profileId: Long, noTraffic: Boolean = false) {
        postUpdate(getProfile(profileId) ?: return, noTraffic)
    }

    suspend fun postUpdate(profile: ProxyEntity, noTraffic: Boolean = false) {
        iterator { onUpdated(profile, noTraffic) }
    }

    suspend fun postUpdate(data: TrafficData) {
        iterator { onUpdated(data) }
    }

    suspend fun createRule(rule: RuleEntity, post: Boolean = true): RuleEntity {
        rule.userOrder = SagerDatabase.rulesDao.nextOrder() ?: 1
        rule.id = SagerDatabase.rulesDao.createRule(rule)
        if (post) {
            ruleIterator { onAdd(rule) }
        }
        return rule
    }

    suspend fun updateRule(rule: RuleEntity) {
        SagerDatabase.rulesDao.updateRule(rule)
        ruleIterator { onUpdated(rule) }
    }

    suspend fun deleteRule(ruleId: Long) {
        SagerDatabase.rulesDao.deleteById(ruleId)
        ruleIterator { onRemoved(ruleId) }
    }

    suspend fun deleteRules(rules: List<RuleEntity>) {
        SagerDatabase.rulesDao.deleteRules(rules)
        ruleIterator {
            rules.forEach {
                onRemoved(it.id)
            }
        }
    }

    @Synchronized
    fun migrateLegacyRoutePresets() {
        val key = "routePresets155Migrated"
        if (DataStore.configurationStore.getBoolean(key, false)) return
        val templates = legacyRoutePresetChanges(app)
        SagerDatabase.instance.runInTransaction {
            for (rule in SagerDatabase.rulesDao.allRules()) {
                val updated = migrateLegacyRoutePreset(rule, templates)
                if (updated == null) SagerDatabase.rulesDao.deleteRule(rule)
                else if (updated != rule) SagerDatabase.rulesDao.updateRule(updated)
            }
        }
        DataStore.configurationStore.putBoolean(key, true)
    }

    suspend fun getRules(): List<RuleEntity> {
        migrateLegacyRoutePresets()
        var rules = SagerDatabase.rulesDao.allRules()
        if (rules.isEmpty() && !DataStore.rulesFirstCreate) {
            DataStore.rulesFirstCreate = true
            createRule(
                RuleEntity(
                    name = app.getString(R.string.route_opt_block_quic),
                    port = "443",
                    network = "udp",
                    outbound = -2
                )
            )
            createRule(
                RuleEntity(
                    name = app.getString(R.string.route_opt_block_ads),
                    domains = "geosite:category-ads-all",
                    outbound = -2
                )
            )
            for (rule in ruRoutePresets()) createRule(rule, false)
            rules = SagerDatabase.rulesDao.allRules()
        }
        return rules
    }

}

// Play Store matching and outbound are deliberately unchanged; only its name changes.
fun ruRoutePresets() = listOf(
    RuleEntity(name = "для RU", domains = "googleapis.cn"),
    RuleEntity(name = "Домены RU — напрямую", domains = "geosite:category-ru", outbound = -1),
    RuleEntity(name = "IP RU — напрямую", ip = "geoip:ru", outbound = -1)
)

fun legacyRoutePresetChanges(context: Context): List<Pair<RuleEntity, RuleEntity?>> {
    val presets = ruRoutePresets()
    // Match old localized names even when the application language has changed.
    val locales = (context.assets.locales.toList() + listOf("en", "ru", "zh-CN", "fa")).distinct()
    return locales.flatMap { tag ->
        val config = Configuration(context.resources.configuration).apply {
            setLocale(Locale.forLanguageTag(tag.replace('_', '-')))
        }
        val localized = context.createConfigurationContext(config)
        buildList {
            add(RuleEntity(name = localized.getString(R.string.route_play_store, "中国"), domains = "googleapis.cn") to presets[0])
            for ((code, country) in listOf("cn" to "中国", "ir" to "Iran", "ru" to "Russia")) {
                add(RuleEntity(name = localized.getString(R.string.route_bypass_domain, country), domains = "geosite:$code", outbound = -1) to if (code == "ru") presets[1] else null)
                add(RuleEntity(name = localized.getString(R.string.route_bypass_ip, country), ip = "geoip:$code", outbound = -1) to if (code == "ru") presets[2] else null)
            }
        }
    }.distinct()
}

fun migrateLegacyRoutePreset(rule: RuleEntity, templates: List<Pair<RuleEntity, RuleEntity?>>): RuleEntity? {
    // No heuristic deletion: require the complete original name and match/action fields.
    // Preserve renamed/extended user rules, identifiers, order and enabled state.
    val original = rule.copy(id = 0, userOrder = 0, enabled = false)
    val match = templates.firstOrNull { it.first == original } ?: return rule
    val replacement = match.second ?: return null
    return rule.copy(name = replacement.name, domains = replacement.domains, ip = replacement.ip)
}
