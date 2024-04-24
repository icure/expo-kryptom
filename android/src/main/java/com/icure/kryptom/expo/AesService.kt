package com.icure.kryptom.expo

import com.icure.kryptom.crypto.AesService
import com.icure.kryptom.crypto.defaultCryptoService

object AesService {
    suspend fun generateKey(size: Int): ByteArray = defaultCryptoService.aes.exportKey(
        defaultCryptoService.aes.generateKey(
            when (size) {
                128 -> AesService.KeySize.Aes128
                256 -> AesService.KeySize.Aes256
                else -> throw IllegalArgumentException("Unsupported key size $size")
            }
        )
    )

    suspend fun encrypt(data: ByteArray, key: ByteArray, iv: ByteArray?): ByteArray = defaultCryptoService.aes.encrypt(
        data = data,
        key = defaultCryptoService.aes.loadKey(key),
        iv = iv
    )

    suspend fun decrypt(ivAndEncryptedData: ByteArray, key: ByteArray): ByteArray = defaultCryptoService.aes.decrypt(
        ivAndEncryptedData = ivAndEncryptedData,
        key = defaultCryptoService.aes.loadKey(key)
    )
}