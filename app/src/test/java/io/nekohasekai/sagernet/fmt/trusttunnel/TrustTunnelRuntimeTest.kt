package io.nekohasekai.sagernet.fmt.trusttunnel

import kotlinx.coroutines.*
import org.junit.Assert.*
import org.junit.Test
import java.io.IOException
import java.net.ServerSocket
import java.net.InetAddress
import kotlin.concurrent.thread

class TrustTunnelRuntimeTest {
    private fun listener() = ServerSocket(0, 5, InetAddress.getByName("127.0.0.1"))

    @Test fun verifiesFragmentedSocksReply() = runBlocking {
        listener().use { server ->
            val worker = thread {
                server.accept().use { s ->
                    val greeting = ByteArray(3)
                    java.io.DataInputStream(s.getInputStream()).readFully(greeting)
                    assertArrayEquals(byteArrayOf(5, 1, 0), greeting)
                    s.getOutputStream().write(5)
                    Thread.sleep(10)
                    s.getOutputStream().write(0)
                }
            }
            awaitTrustTunnelSocks(server.localPort)
            worker.join(1000)
            assertFalse(worker.isAlive)
        }
    }
    @Test fun closedPortIsNotSuccess() = runBlocking {
        val port = listener().use { it.localPort }
        try { awaitTrustTunnelSocks(port, 150); fail("accepted closed port") }
        catch (e: IOException) { assertTrue(e.message!!.contains("not-listening")) }
    }
    @Test fun acceptsNoPlainTcpOrHttpListener() = runBlocking {
        listener().use { server ->
            val worker = thread {
                while (!server.isClosed) {
                    try { server.accept().use { it.getOutputStream().write("HTTP/1.1 200 OK\r\n".toByteArray()) } }
                    catch (_: IOException) { break }
                }
            }
            try { awaitTrustTunnelSocks(server.localPort, 200); fail("accepted HTTP listener") }
            catch (e: IOException) { assertTrue(e.message!!.contains("local SOCKS5 not ready")) }
            finally { server.close(); worker.join(1000) }
        }
    }
    @Test fun cancellationDoesNotBecomeTimeoutOrSuccess() = runBlocking {
        listener().use { server ->
            // Backlog accepts TCP, but no peer ever answers SOCKS negotiation.
            var completed = false
            val job = launch { awaitTrustTunnelSocks(server.localPort, 5000); completed = true }
            delay(50)
            val start = System.nanoTime()
            job.cancelAndJoin()
            assertTrue(job.isCancelled)
            assertFalse(completed)
            assertTrue("cancellation blocked", System.nanoTime() - start < 1_000_000_000)
        }
    }
    @OptIn(ExperimentalCoroutinesApi::class, DelicateCoroutinesApi::class)
    @Test fun probeDoesNotBlockCallingDispatcher() = runBlocking {
        newSingleThreadContext("simulated-ui").use { ui ->
            listener().use { server ->
                val callerThread = withContext(ui) { Thread.currentThread() }
                val job = launch(ui) { awaitTrustTunnelSocks(server.localPort, 5000) }
                try {
                    delay(30)
                    withTimeout(1000) { withContext(ui) { assertSame(callerThread, Thread.currentThread()) } }
                } finally { job.cancelAndJoin() }
            }
        }
    }
    @Test fun startupLogHasNoConfiguration() {
        assertEquals("TrustTunnel configuration prepared (credentials hidden)", trustTunnelConfigLogMessage())
    }
}
