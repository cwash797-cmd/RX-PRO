package io.nekohasekai.sagernet.fmt.trusttunnel

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.io.DataInputStream
import java.io.EOFException
import java.io.IOException
import java.net.ConnectException
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException

/** Loopback only: no CONNECT request and no upstream traffic before sing-box starts. */
suspend fun awaitTrustTunnelSocks(port: Int, timeoutMillis: Long = 5000) = withContext(Dispatchers.IO) {
    require(port in 1..65535 && timeoutMillis > 0)
    val deadline = System.nanoTime() + timeoutMillis * 1_000_000
    var reason = "not-listening"
    while (System.nanoTime() < deadline) {
        currentCoroutineContext().ensureActive()
        val remaining = ((deadline - System.nanoTime()) / 1_000_000).coerceIn(1, 100).toInt()
        try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress("127.0.0.1", port), remaining)
                socket.soTimeout = remaining
                socket.getOutputStream().write(byteArrayOf(5, 1, 0))
                val response = ByteArray(2)
                DataInputStream(socket.getInputStream()).readFully(response)
                if (response.contentEquals(byteArrayOf(5, 0))) return@withContext
                reason = "invalid-socks-reply"
            }
        } catch (_: ConnectException) {
            reason = "not-listening"
        } catch (_: SocketTimeoutException) {
            reason = "handshake-timeout"
        } catch (_: EOFException) {
            reason = "handshake-closed"
        } catch (_: IOException) {
            reason = "local-io-error"
        }
        currentCoroutineContext().ensureActive()
        delay(25)
    }
    throw IOException("TrustTunnel local SOCKS5 not ready [$reason]. Check adapter startup logs.")
}

fun trustTunnelConfigLogMessage(): String = "TrustTunnel configuration prepared (credentials hidden)"
