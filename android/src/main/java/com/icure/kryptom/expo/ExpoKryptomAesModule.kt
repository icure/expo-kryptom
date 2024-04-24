package com.icure.kryptom.expo

import expo.modules.kotlin.functions.Coroutine
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition

class ExpoKryptomModule : Module() {
  override fun definition() = ModuleDefinition {
    Name("ExpoKryptom")

    AsyncFunction("generateKeyAes") Coroutine { size: Int ->
      AesService.generateKey(size = size)
    }

    AsyncFunction("encryptAes") Coroutine { data: ByteArray, key: ByteArray, iv: ByteArray? ->
      AesService.encrypt(
        data = data,
        key = key,
        iv = iv
      )
    }

    AsyncFunction("decryptAes") Coroutine { ivAndEncryptedData: ByteArray, key: ByteArray ->
      AesService.decrypt(
        ivAndEncryptedData = ivAndEncryptedData,
        key = key
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
