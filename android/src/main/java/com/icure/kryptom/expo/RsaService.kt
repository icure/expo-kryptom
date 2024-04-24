package com.icure.kryptom.expo

import com.icure.kryptom.crypto.RsaAlgorithm
import com.icure.kryptom.crypto.RsaKeypair
import com.icure.kryptom.crypto.RsaService
import com.icure.kryptom.crypto.defaultCryptoService

object RsaService {

    private suspend fun keyPairToMap(keyPair: RsaKeypair<RsaAlgorithm>) = mapOf(
        "public" to defaultCryptoService.rsa.exportPublicKeySpki(keyPair.public),
        "private" to defaultCryptoService.rsa.exportPrivateKeyPkcs8(keyPair.private),
        "algorithmIdentifier" to keyPair.algorithm.identifier
    )
    suspend fun generateKey(
        algorithmIdentifier: String,
        size: Int
    ): Map<String, Any> = defaultCryptoService.rsa.generateKeyPair(
        algorithm = RsaAlgorithm.fromIdentifier(algorithmIdentifier),
        keySize = when (size) {
            2048 -> RsaService.KeySize.Rsa2048
            4096 -> RsaService.KeySize.Rsa4096
            else -> throw IllegalArgumentException("Invalid size provided to generate a RSA Key: $size")
        }
    ).let {
        keyPairToMap(it)
    }
}