package com.icure.kryptom.expo

import expo.modules.kotlin.functions.Coroutine
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition

class ExpoKryptomModule : Module() {
  override fun definition() = ModuleDefinition {
    Name("ExpoKryptom")

    AsyncFunction("generateKey") Coroutine { size: Int ->
      AesService.generateKey(size = size)
    }

    AsyncFunction("encrypt") Coroutine { data: ByteArray, key: ByteArray, iv: ByteArray? ->
      AesService.encrypt(
        data = data,
        key = key,
        iv = iv
      )
    }

    AsyncFunction("decrypt") Coroutine { ivAndEncryptedData: ByteArray, key: ByteArray ->
      AesService.decrypt(
        ivAndEncryptedData = ivAndEncryptedData,
        key = key
      )
    }
  }
}
