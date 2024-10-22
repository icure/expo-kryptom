package com.icure.kryptom.expo

import com.icure.kryptom.crypto.RsaAlgorithm
import com.icure.kryptom.crypto.RsaKeypair
import com.icure.kryptom.crypto.RsaService
import com.icure.kryptom.crypto.defaultCryptoService
import com.icure.kryptom.expo.ExportPrivateRsaKeyJwk.Companion.toExport
import com.icure.kryptom.expo.ExportPublicRsaKeyJwk.Companion.toExport

object RsaService {

    private suspend fun RsaKeypair<RsaAlgorithm>.toMap() = mapOf(
        "public" to mapOf(
            "publicKey" to defaultCryptoService.rsa.exportPublicKeySpki(public),
            "algorithm" to public.algorithm.identifier
        ),
        "private" to mapOf(
            "privateKey" to defaultCryptoService.rsa.exportPrivateKeyPkcs8(private),
            "algorithm" to private.algorithm.identifier
        ),
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
    ).toMap()

    suspend fun decrypt(data: ByteArray, privateKey: ByteArray, algorithmIdentifier: String): ByteArray = defaultCryptoService.rsa.decrypt(
        data = data,
        privateKey = defaultCryptoService.rsa.loadPrivateKeyPkcs8(
            privateKeyPkcs8 = privateKey,
            algorithm = RsaAlgorithm.RsaEncryptionAlgorithm.fromIdentifier(algorithmIdentifier)
        )
    )

    suspend fun encrypt(data: ByteArray, publicKey: ByteArray, algorithmIdentifier: String): ByteArray = defaultCryptoService.rsa.encrypt(
        data = data,
        publicKey = defaultCryptoService.rsa.loadPublicKeySpki(
            publicKeySpki = publicKey,
            algorithm = RsaAlgorithm.RsaEncryptionAlgorithm.fromIdentifier(algorithmIdentifier)
        )
    )

    suspend fun exportPrivateKeyJwk(privateKey: ByteArray, algorithmIdentifier: String): ExportPrivateRsaKeyJwk = defaultCryptoService.rsa.exportPrivateKeyJwk(
        key = defaultCryptoService.rsa.loadPrivateKeyPkcs8(
            privateKeyPkcs8 = privateKey,
            algorithm = RsaAlgorithm.fromIdentifier(algorithmIdentifier)
        )
    ).toExport()

    suspend fun exportPublicKeyJwk(publicKey: ByteArray, algorithmIdentifier: String): ExportPublicRsaKeyJwk = defaultCryptoService.rsa.exportPublicKeyJwk(
        key = defaultCryptoService.rsa.loadPublicKeySpki(
            publicKeySpki = publicKey,
            algorithm = RsaAlgorithm.fromIdentifier(algorithmIdentifier)
        )
    ).toExport()

    suspend fun importPrivateKeyJwk(privateKey: ExportPrivateRsaKeyJwk) = defaultCryptoService.rsa.loadPrivateKeyJwk(
        algorithm = RsaAlgorithm.fromJwkIdentifier(privateKey.alg),
        privateKeyJwk = privateKey.toPrivateRsaKeyJwk()
    ).let {
        mapOf(
            "privateKey" to defaultCryptoService.rsa.exportPrivateKeyPkcs8(it),
            "algorithm" to it.algorithm.identifier,
        )
    }

    suspend fun importPublicKeyJwk(publicKey: ExportPublicRsaKeyJwk) = defaultCryptoService.rsa.loadPublicKeyJwk(
        algorithm = RsaAlgorithm.fromJwkIdentifier(publicKey.alg),
        publicKeyJwk = publicKey.toPublicRsaKeyJwk()
    ).let {
        mapOf(
            "publicKey" to defaultCryptoService.rsa.exportPublicKeySpki(it),
            "algorithm" to it.algorithm.identifier,
        )
    }

    suspend fun importKeyPair(privateKey: ByteArray, algorithmIdentifier: String) = defaultCryptoService.rsa.loadKeyPairPkcs8(
        algorithm = RsaAlgorithm.fromIdentifier(algorithmIdentifier),
        privateKeyPkcs8 = privateKey
    ).toMap()

    suspend fun signature(data: ByteArray, privateKey: ByteArray, algorithmIdentifier: String): ByteArray = defaultCryptoService.rsa.sign(
        data = data,
        privateKey = defaultCryptoService.rsa.loadPrivateKeyPkcs8(
            algorithm = RsaAlgorithm.RsaSignatureAlgorithm.fromIdentifier(algorithmIdentifier),
            privateKeyPkcs8 = privateKey
        )
    )

    suspend fun verify(signature: ByteArray, data: ByteArray, publicKey: ByteArray, algorithmIdentifier: String): Boolean = defaultCryptoService.rsa.verifySignature(
        data = data,
        signature = signature,
        publicKey = defaultCryptoService.rsa.loadPublicKeySpki(
            algorithm = RsaAlgorithm.RsaSignatureAlgorithm.fromIdentifier(algorithmIdentifier),
            publicKeySpki = publicKey
        )
    )
}