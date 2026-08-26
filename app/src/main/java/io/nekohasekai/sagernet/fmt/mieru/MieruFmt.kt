/******************************************************************************
 * Copyright (C) 2022 by nekohasekai <contact-git@sekai.icu>                  *
 *                                                                            *
 * This program is free software: you can redistribute it and/or modify       *
 * it under the terms of the GNU General Public License as published by       *
 * the Free Software Foundation, either version 3 of the License, or          *
 *  (at your option) any later version.                                       *
 *                                                                            *
 * This program is distributed in the hope that it will be useful,            *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of             *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the              *
 * GNU General Public License for more details.                               *
 *                                                                            *
 * You should have received a copy of the GNU General Public License          *
 * along with this program. If not, see <http://www.gnu.org/licenses/>.       *
 *                                                                            *
 ******************************************************************************/

package io.nekohasekai.sagernet.fmt.mieru

import io.nekohasekai.sagernet.ktx.toStringPretty
import io.nekohasekai.sagernet.ktx.unUrlSafe
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import org.json.JSONArray
import org.json.JSONObject

// RX-PRO: parse mierus:// share links (mieru official URI scheme, used by RIXXX panel)
// Format: mierus://username:password@host?profile=default&port=2012&protocol=TCP&multiplexing=...#name
fun parseMieru(link: String): MieruBean {
    val url = ("https://" + link.substringAfter("://")).toHttpUrlOrNull()
        ?: error("Invalid mieru link: $link")
    return MieruBean().apply {
        serverAddress = url.host
        // port comes as a query parameter, not in the authority
        serverPort = url.queryParameter("port")?.toIntOrNull()
            ?: if (url.port != 443) url.port else 2012
        username = url.username
        password = url.password
        protocol = url.queryParameter("protocol")?.uppercase() ?: "TCP"
        url.queryParameter("mtu")?.toIntOrNull()?.let { mtu = it }
        name = url.fragment?.unUrlSafe() ?: ""
        initializeDefaultValues()
    }
}

fun MieruBean.buildMieruConfig(port: Int): String {
    val serverInfo = JSONArray().apply {
        put(JSONObject().apply {
            put("ipAddress", finalAddress)
            put("portBindings", JSONArray().apply {
                put(JSONObject().apply {
                    put("port", finalPort)
                    put("protocol", protocol)
                })
            })
        })
    }
    return JSONObject().apply {
        put("activeProfile", "default")
        put("socks5Port", port)
        // TODO: follow NekoBox logging level.
        put("loggingLevel", "INFO")
        put("profiles", JSONArray().apply {
            put(JSONObject().apply {
                put("profileName", "default")
                put("user", JSONObject().apply {
                    put("name", username)
                    put("password", password)
                })
                put("servers", serverInfo)
                put("mtu", mtu)
            })
        })
    }.toStringPretty()
}
