package com.icure.kryptom.expo

import com.icure.kryptom.crypto.defaultCryptoService

object DigestService {
    suspend fun sha256(data: ByteArray): ByteArray =
        defaultCryptoService.digest.sha256(data)

    suspend fun sha512(data: ByteArray): ByteArray =
        defaultCryptoService.digest.sha512(data)
}