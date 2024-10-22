package com.icure.kryptom.expo

import expo.modules.kotlin.functions.Coroutine
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition

class ExpoKryptomModule : Module() {
  override fun definition() = ModuleDefinition {
    Name("ExpoKryptom")

    Constants(
      "rsaKeyNeedsExport" to false
    )

    AsyncFunction("generateKeyAes") Coroutine { algorithmIdentifier: String, size: Int ->
      AesService.generateKey(algorithmIdentifier = algorithmIdentifier, size = size)
    }

    AsyncFunction("encryptAes") Coroutine { data: ByteArray, key: ByteArray, algorithmIdentifier: String, iv: ByteArray? ->
      AesService.encrypt(
        data = data,
        key = key,
        algorithmIdentifier = algorithmIdentifier,
        iv = iv
      )
    }

    AsyncFunction("decryptAes") Coroutine { ivAndEncryptedData: ByteArray, key: ByteArray, algorithmIdentifier: String ->
      AesService.decrypt(
        ivAndEncryptedData = ivAndEncryptedData,
        key = key,
        algorithmIdentifier = algorithmIdentifier
      )
    }

    AsyncFunction("exportKeyAes") Coroutine { key: ByteArray, algorithmIdentifier: String ->
      AesService.exportKey(
        key = key,
        algorithmIdentifier = algorithmIdentifier
      )
    }

    AsyncFunction("generateKeyRsa") Coroutine { algorithmIdentifier: String, size: Int ->
      RsaService.generateKey(
        algorithmIdentifier = algorithmIdentifier,
        size = size
      )
    }

    AsyncFunction("decryptRsa") Coroutine { data: ByteArray, privateKey: ByteArray, algorithmIdentifier: String ->
      RsaService.decrypt(
        data = data,
        privateKey = privateKey,
        algorithmIdentifier = algorithmIdentifier
      )
    }

    AsyncFunction("encryptRsa") Coroutine { data: ByteArray, publicKey: ByteArray, algorithmIdentifier: String ->
      RsaService.encrypt(
        data = data,
        publicKey = publicKey,
        algorithmIdentifier = algorithmIdentifier
      )
    }

    AsyncFunction("exportPrivateKeyJwkRsa") Coroutine { privateKey: ByteArray, algorithmIdentifier: String ->
      RsaService.exportPrivateKeyJwk(
        privateKey = privateKey,
        algorithmIdentifier = algorithmIdentifier
      )
    }

    AsyncFunction("exportPublicKeyJwkRsa") Coroutine { publicKey: ByteArray, algorithmIdentifier: String ->
      RsaService.exportPublicKeyJwk(
        publicKey = publicKey,
        algorithmIdentifier = algorithmIdentifier
      )
    }

    AsyncFunction("importPrivateKeyJwkRsa") Coroutine { privateKey: ExportPrivateRsaKeyJwk ->
      RsaService.importPrivateKeyJwk(
        privateKey = privateKey,
      )
    }

    AsyncFunction("importPublicKeyJwkRsa") Coroutine { publicKey: ExportPublicRsaKeyJwk ->
      RsaService.importPublicKeyJwk(
        publicKey = publicKey,
      )
    }

    AsyncFunction("importKeyPairRsa") Coroutine { privateKey: ByteArray, algorithmIdentifier: String ->
      RsaService.importKeyPair(
        privateKey = privateKey,
        algorithmIdentifier = algorithmIdentifier
      )
    }

    AsyncFunction("signatureRsa") Coroutine { data: ByteArray, privateKey: ByteArray, algorithmIdentifier: String ->
      RsaService.signature(
        data = data,
        privateKey = privateKey,
        algorithmIdentifier = algorithmIdentifier
      )
    }

    AsyncFunction("verifyRsa") Coroutine { signature: ByteArray, data: ByteArray, publicKey: ByteArray, algorithmIdentifier: String ->
      RsaService.verify(
        signature = signature,
        data = data,
        publicKey = publicKey,
        algorithmIdentifier = algorithmIdentifier
      )
    }

    AsyncFunction("generateKeyHmac") Coroutine { algorithmIdentifier: String ->
      HmacService.generateKey(algorithmIdentifier = algorithmIdentifier)
    }

    AsyncFunction("signHmac") Coroutine { algorithmIdentifier: String, key: ByteArray, data: ByteArray ->
      HmacService.sign(
        algorithmIdentifier = algorithmIdentifier,
        key = key,
        data = data
      )
    }

    AsyncFunction("verifyHmac") Coroutine { algorithmIdentifier: String, key: ByteArray, signature: ByteArray, data: ByteArray ->
      HmacService.verify(
        algorithmIdentifier = algorithmIdentifier,
        key = key,
        signature = signature,
        data = data
      )
    }

    AsyncFunction("sha256") Coroutine { data: ByteArray ->
      DigestService.sha256(data)
    }

    Function("randomBytes") { length: Int ->
      StrongRandom.randomBytes(length)
    }

    Function("randomUUID") {
      StrongRandom.randomUUID()
    }
  }
}
