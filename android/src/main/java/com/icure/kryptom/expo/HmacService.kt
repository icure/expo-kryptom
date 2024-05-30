package com.icure.kryptom.expo

import com.icure.kryptom.crypto.HmacAlgorithm
import com.icure.kryptom.crypto.HmacKey
import com.icure.kryptom.crypto.defaultCryptoService

object HmacService {
    suspend fun generateKey(algorithmIdentifier: String): Map<String, Any> =
        defaultCryptoService.hmac.generateKey(
            HmacAlgorithm.fromIdentifier(algorithmIdentifier)
        ).toMap()

    suspend fun sign(
        algorithmIdentifier: String,
        key: ByteArray,
        data: ByteArray,
    ): ByteArray =
        defaultCryptoService.hmac.loadKey(
            HmacAlgorithm.fromIdentifier(algorithmIdentifier),
            key
        ).let {
            defaultCryptoService.hmac.sign(data, it)
        }

    suspend fun verify(
        algorithmIdentifier: String,
        key: ByteArray,
        signature: ByteArray,
        data: ByteArray
    ) =
        defaultCryptoService.hmac.loadKey(
            HmacAlgorithm.fromIdentifier(algorithmIdentifier),
            key
        ).let {
            defaultCryptoService.hmac.verify(signature = signature, data = data, key = it)
        }

    private suspend fun HmacKey<*>.toMap(): Map<String, Any> = mapOf(
        "algorithmIdentifier" to algorithm.identifier,
        "key" to defaultCryptoService.hmac.exportKey(this)
    )
}