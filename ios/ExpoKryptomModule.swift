import ExpoModulesCore

public class ExpoKryptomModule: Module {
    public func definition() -> ModuleDefinition {
        Name("ExpoKryptom")
        
        AsyncFunction("generateKeyAes") { (size: Int32, promise: Promise) in
            guard let keySize = AesKeySize(rawValue: size) else {
                promise.reject(Exception(name: "IllegalArgument", description: "Unsupported key size \(size)"))
                return
            }
            AesKryptomWrapper.shared.generateKey(size: keySize, promise: promise)
        }
        
        AsyncFunction("encryptAes") { (data: Data, key: Data, iv: Data?, promise: Promise) in
            AesKryptomWrapper.shared.encrypt(data: data, key: key, iv: iv, promise: promise)
        }
        
        AsyncFunction("decryptAes") { (ivAndEncryptedData: Data, key: Data, promise: Promise) in
            AesKryptomWrapper.shared.decrypt(ivAndEncryptedData: ivAndEncryptedData, key: key, promise: promise)
        }
        
        AsyncFunction("generateKeyRsa") { (algorithmIdentifier: String, size: Int32, promise: Promise) in
            RsaKryptomWrapper.shared.generateKey(algorithmIdentifier: algorithmIdentifier, size: size, promise: promise)
        }
    }
}
