package com.icure.kryptom.expo

import com.icure.kryptom.crypto.AesAlgorithm
import com.icure.kryptom.crypto.AesKey
import com.icure.kryptom.crypto.AesService
import com.icure.kryptom.crypto.defaultCryptoService

object AesService {
    suspend fun generateKey(algorithmIdentifier: String, size: Int): Map<String, Any> =
        defaultCryptoService.aes.generateKey(
            AesAlgorithm.fromIdentifier(algorithmIdentifier),
            when (size) {
                128 -> AesService.KeySize.Aes128
                256 -> AesService.KeySize.Aes256
                else -> throw IllegalArgumentException("Unsupported key size $size")
            }
        ).toMap()

    suspend fun encrypt(data: ByteArray, key: ByteArray, algorithmIdentifier: String, iv: ByteArray?): ByteArray = defaultCryptoService.aes.encrypt(
        data = data,
        key = defaultCryptoService.aes.loadKey(
            AesAlgorithm.fromIdentifier(algorithmIdentifier),
            key
        ),
        iv = iv
    )

    suspend fun decrypt(ivAndEncryptedData: ByteArray, key: ByteArray, algorithmIdentifier: String): ByteArray = defaultCryptoService.aes.decrypt(
        ivAndEncryptedData = ivAndEncryptedData,
        key = defaultCryptoService.aes.loadKey(
            AesAlgorithm.fromIdentifier(algorithmIdentifier),
            key
        )
    )

    suspend fun exportKey(key: ByteArray, algorithmIdentifier: String) = defaultCryptoService.aes.exportKey(
        key = defaultCryptoService.aes.loadKey(
            AesAlgorithm.fromIdentifier(algorithmIdentifier),
            key
        )
    )

    private suspend fun AesKey<*>.toMap(): Map<String, Any> = mapOf(
        "algorithmIdentifier" to algorithm.identifier,
        "key" to defaultCryptoService.aes.exportKey(this)
    )
}