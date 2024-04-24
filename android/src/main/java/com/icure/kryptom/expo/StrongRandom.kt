package com.icure.kryptom.expo

import com.icure.kryptom.crypto.defaultCryptoService

object StrongRandom {
    fun randomBytes(length: Int): ByteArray =
        defaultCryptoService.strongRandom.randomBytes(length)

    fun randomUUID(): String =
        defaultCryptoService.strongRandom.randomUUID()
}