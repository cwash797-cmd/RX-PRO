/******************************************************************************
 * RX-PRO: profile editor for VLESS XHTTP profiles (run via bundled Xray-core) *
 *                                                                            *
 * This program is free software: you can redistribute it and/or modify       *
 * it under the terms of the GNU General Public License as published by       *
 * the Free Software Foundation, either version 3 of the License, or          *
 *  (at your option) any later version.                                       *
 ******************************************************************************/

package io.nekohasekai.sagernet.ui.profile

import android.os.Bundle
import androidx.preference.EditTextPreference
import androidx.preference.PreferenceFragmentCompat
import io.nekohasekai.sagernet.Key
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.database.preference.EditTextPreferenceModifiers
import io.nekohasekai.sagernet.fmt.xhttp.XhttpBean
import io.nekohasekai.sagernet.ktx.applyDefaultValues
import moe.matsuri.nb4a.proxy.PreferenceBinding
import moe.matsuri.nb4a.proxy.PreferenceBindingManager
import moe.matsuri.nb4a.proxy.Type

class XhttpSettingsActivity : ProfileSettingsActivity<XhttpBean>() {

    override fun createEntity() = XhttpBean().applyDefaultValues()

    private val pbm = PreferenceBindingManager()
    private val name = pbm.add(PreferenceBinding(Type.Text, "name"))
    private val serverAddress = pbm.add(PreferenceBinding(Type.Text, "serverAddress"))
    private val serverPort = pbm.add(PreferenceBinding(Type.TextToInt, "serverPort"))
    private val uuid = pbm.add(PreferenceBinding(Type.Text, "uuid"))
    private val mode = pbm.add(PreferenceBinding(Type.Text, "mode"))
    private val path = pbm.add(PreferenceBinding(Type.Text, "path"))
    private val host = pbm.add(PreferenceBinding(Type.Text, "host"))
    private val extraJson = pbm.add(PreferenceBinding(Type.Text, "extraJson"))
    private val security = pbm.add(PreferenceBinding(Type.Text, "security"))
    private val sni = pbm.add(PreferenceBinding(Type.Text, "sni"))
    private val alpn = pbm.add(PreferenceBinding(Type.Text, "alpn"))
    private val fingerprint = pbm.add(PreferenceBinding(Type.Text, "fingerprint"))
    private val allowInsecure = pbm.add(PreferenceBinding(Type.Bool, "allowInsecure"))

    // RX-PRO v1.5.0: REALITY support for XHTTP profiles
    private val realityPublicKey = pbm.add(PreferenceBinding(Type.Text, "realityPublicKey"))
    private val realityShortId = pbm.add(PreferenceBinding(Type.Text, "realityShortId"))
    private val realitySpiderX = pbm.add(PreferenceBinding(Type.Text, "realitySpiderX"))

    override fun XhttpBean.init() {
        pbm.writeToCacheAll(this)
    }

    override fun XhttpBean.serialize() {
        pbm.fromCacheAll(this)
    }

    override fun PreferenceFragmentCompat.createPreferences(
        savedInstanceState: Bundle?,
        rootKey: String?,
    ) {
        addPreferencesFromResource(R.xml.xhttp_preferences)

        findPreference<EditTextPreference>(Key.SERVER_PORT)!!.apply {
            setOnBindEditTextListener(EditTextPreferenceModifiers.Port)
        }
    }
}
