import ExpoModulesCore
//import Kryptom

public class ExpoKryptomModule: Module {
  public func definition() -> ModuleDefinition {
    //let aes = CryptoServiceKt.defaultCryptoService.aes

    Name("ExpoKryptom")

    AsyncFunction("generateKey") { (size: Int32, promise: Promise) in
        promise.resolve(Data(repeating: 8, count: 16))
        /*
      guard size == 128 || size == 256 else {
          promise.reject(Exception(name: "IllegalArgument", description: "Unsupported key size \(size)"))
          return
      }

      aes.generateKey(size: (size == 128) ? .aes128 : .aes256) { result, error in
          guard let error = error else {
            guard let result = result else {
              fatalError("Result of key generation is null")
            }
            promise.resolve(result.toNSData())
            return
          }
          promise.reject(error)
      }
         */
    }

    AsyncFunction("encrypt") { (data: Data, key: Data, iv: Data?, promise: Promise) in
        promise.resolve(Data(repeating: 7, count: 16))
        /*
      let kData = NSDataUtilsKt.toByteArray(data)
      let kKey = NSDataUtilsKt.toByteArray(key)
      let kIv = iv.flatMap { NSDataUtilsKt.toByteArray($0) }
      aes.encrypt(data: kData, key: kKey, iv: kIv) { result, error in
        guard let error = error else {
          guard let result = result else {
            fatalError("Result is null")
          }
          promise.resolve(result.toNSData())
          return
        }
        promise.reject(error)
      }
         */
    }

    AsyncFunction("decrypt") { (ivAndEncryptedData: Data, key: Data, promise: Promise) in
        promise.resolve(Data(repeating: 6, count: 16))
        /*
      let kData = NSDataUtilsKt.toByteArray(ivAndEncryptedData)
      let kKey = NSDataUtilsKt.toByteArray(key)
      aes.decrypt(ivAndEncryptedData: kData, key: kKey) { result, error in
        guard let error = error else {
          guard let result = result else {
            fatalError("Result is null")
          }
          promise.resolve(result.toNSData())
          return
        }
        promise.reject(error)
      }
         */
    }
  }
}
