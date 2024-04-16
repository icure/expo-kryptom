package com.icure.kryptom.expo

import com.icure.kryptom.crypto.AesService
import expo.modules.kotlin.functions.Coroutine
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import com.icure.kryptom.crypto.defaultCryptoService

class ExpoKryptomModule : Module() {
  override fun definition() = ModuleDefinition {
    Name("ExpoKryptom")

    AsyncFunction("generateKey") Coroutine { size: Int ->
      val key = defaultCryptoService.aes.generateKey(when (size) {
        128 -> AesService.KeySize.AES_128
        256 -> AesService.KeySize.AES_256
        else -> throw IllegalArgumentException("Unsupported key size $size")
      })
      defaultCryptoService.aes.exportKey(key)
    }

    AsyncFunction("encrypt") Coroutine { data: ByteArray, key: ByteArray, iv: ByteArray? ->
      val loadedKey = defaultCryptoService.aes.loadKey(key)
      defaultCryptoService.aes.encrypt(data, loadedKey, iv)
    }

    AsyncFunction("decrypt") Coroutine { ivAndEncryptedData: ByteArray, key: ByteArray ->
      val loadedKey = defaultCryptoService.aes.loadKey(key)
      defaultCryptoService.aes.decrypt(ivAndEncryptedData, loadedKey)
    }
  }
}
