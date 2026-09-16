package io.nekohasekai.sagernet.bg

import java.io.Closeable

interface AbstractInstance : Closeable {

    suspend fun launch()

}