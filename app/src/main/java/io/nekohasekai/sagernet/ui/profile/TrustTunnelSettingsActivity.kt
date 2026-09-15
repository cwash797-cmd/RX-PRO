package io.nekohasekai.sagernet.ui.profile

import android.os.Bundle
import android.text.InputType
import android.widget.Toast
import androidx.preference.EditTextPreference
import androidx.preference.PreferenceFragmentCompat
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.fmt.trusttunnel.TrustTunnelBean
import io.nekohasekai.sagernet.fmt.trusttunnel.parseTrustTunnel
import io.nekohasekai.sagernet.fmt.trusttunnel.toUri
import io.nekohasekai.sagernet.ktx.applyDefaultValues
import io.nekohasekai.sagernet.ktx.onMainDispatcher
import moe.matsuri.nb4a.proxy.PreferenceBinding
import moe.matsuri.nb4a.proxy.PreferenceBindingManager
import moe.matsuri.nb4a.proxy.Type

class TrustTunnelSettingsActivity : ProfileSettingsActivity<TrustTunnelBean>() {
    override fun createEntity() = TrustTunnelBean().applyDefaultValues().apply { serverPort = 443 }
    private val pbm = PreferenceBindingManager().apply {
        listOf("name", "serverAddress", "hostname", "sni", "username", "password",
            "clientRandomPrefix", "certificate", "upstreamProtocol", "dnsUpstreams", "addresses")
            .forEach { add(PreferenceBinding(Type.Text, it)) }
        add(PreferenceBinding(Type.TextToInt, "serverPort"))
        listOf("hasIpv6", "skipVerification", "antiDpi").forEach { add(PreferenceBinding(Type.Bool, it)) }
    }
    override fun TrustTunnelBean.init() = pbm.writeToCacheAll(this)
    override fun TrustTunnelBean.serialize() { pbm.fromCacheAll(this) }

    override suspend fun saveAndExit() {
        val candidate = createEntity().apply { serialize() }
        val valid = runCatching {
            require(candidate.serverPort in 1..65535)
            parseTrustTunnel(candidate.toUri())
        }.isSuccess
        if (!valid) {
            onMainDispatcher { Toast.makeText(this@TrustTunnelSettingsActivity,
                "TrustTunnel: проверьте адрес, порт, логин, пароль и TLS-параметры.", Toast.LENGTH_LONG).show() }
            return
        }
        super.saveAndExit()
    }
    override fun PreferenceFragmentCompat.createPreferences(savedInstanceState: Bundle?, rootKey: String?) {
        addPreferencesFromResource(R.xml.trusttunnel_preferences)
        findPreference<EditTextPreference>("serverPort")!!.setOnBindEditTextListener {
            it.inputType = InputType.TYPE_CLASS_NUMBER
        }
        findPreference<EditTextPreference>("password")!!.apply {
            summaryProvider = androidx.preference.Preference.SummaryProvider<EditTextPreference> {
                if (it.text.isNullOrEmpty()) "Не задан" else "Сохранён"
            }
            setOnBindEditTextListener { it.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD }
        }
    }
}
