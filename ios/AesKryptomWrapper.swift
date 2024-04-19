import ExpoModulesCore
import Kryptom

enum AesKeySize: Int32 {
    case aes128 = 128
    case aes256 = 256
    
    func toAesServiceKeySize() -> AesServiceKeySize {
        switch self {
        case .aes128:
            return .aes128
        case .aes256:
            return .aes256
        }
    }
}

public class AesKryptomWrapper {
    static let shared = AesKryptomWrapper()
    private let aes = CryptoServiceKt.defaultCryptoService.aes
    
    private init() { }
    
    func generateKey(size: AesKeySize, promise: Promise) {
        let keySize = size.toAesServiceKeySize()
        aes.generateKey(size: keySize) { result, error in
            if let generateKeyError = error {
                promise.reject(generateKeyError)
                return
            }
            
            guard let result = result else {
                fatalError("Result is null")
            }
            
            promise.resolve(result.toNSData())
        }
    }
    
    func encrypt(data: Data, key: Data, iv: Data?, promise: Promise) {
        let kData = NSDataUtilsKt.toByteArray(data)
        let kKey = NSDataUtilsKt.toByteArray(key)
        let kIv = iv.flatMap { NSDataUtilsKt.toByteArray($0) }
        aes.encrypt(data: kData, key: kKey, iv: kIv) { result, error in
            if let encryptError = error {
                promise.reject(encryptError)
                return
            }
            
            guard let result = result else {
                fatalError("Result is null")
            }
            promise.resolve(result.toNSData())
        }
    }
    
    func decrypt(ivAndEncryptedData: Data, key: Data, promise: Promise) {
        let kData = NSDataUtilsKt.toByteArray(ivAndEncryptedData)
        let kKey = NSDataUtilsKt.toByteArray(key)
        aes.decrypt(ivAndEncryptedData: kData, key: kKey) { result, error in
            if let decryptError = error {
                promise.reject(decryptError)
                return
            }
            
            guard let result = result else {
                fatalError("Result is null")
            }
            promise.resolve(result.toNSData())
        }
    }
}
