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

public struct AesKryptomWrapper {
    private static let aes = CryptoServiceKt.defaultCryptoService.aes
    
    static func generateKey(size: AesKeySize) async throws -> Data {
        let keySize = size.toAesServiceKeySize()
        let aesKey = try await aes.generateKey(size: keySize)
        
        print("Generated")
        
        return aesKey.toNSData()
    }
    
    static func encrypt(data: Data, key: Data, iv: Data?) async throws -> Data {
        let kData = NSDataUtilsKt.toByteArray(data)
        let kKey = NSDataUtilsKt.toByteArray(key)
        let kIv = iv.flatMap { NSDataUtilsKt.toByteArray($0) }
        let encryptedData = try await aes.encrypt(data: kData, key: kKey, iv: kIv)
        
        return encryptedData.toNSData()
    }
    
    static func decrypt(ivAndEncryptedData: Data, key: Data) async throws -> Data {
        let kData = NSDataUtilsKt.toByteArray(ivAndEncryptedData)
        let kKey = NSDataUtilsKt.toByteArray(key)
        let decryptedData = try await aes.decrypt(ivAndEncryptedData: kData, key: kKey)
        
        return decryptedData.toNSData()
    }
}
