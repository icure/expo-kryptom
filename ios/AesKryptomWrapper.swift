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
    
    static func generateKey(algorithmIdentifier: String, size: AesKeySize) async throws -> [String: Any] {
        let keySize = size.toAesServiceKeySize()
        let algorithm = try AesAlgorithmCompanion.shared.fromIdentifier(identifier: algorithmIdentifier)
        let aesKey = try await aes.generateKey(algorithm: algorithm, size: keySize)
        
        return mapKeyToDictonary(key: aesKey)
    }
    
    static func encrypt(data: Data, key: Data, algorithmIdentifier: String, iv: Data?) async throws -> Data {
        let kData = NSDataUtilsKt.toByteArray(data)
        let kRawKey = NSDataUtilsKt.toByteArray(key)
        let algorithm = try AesAlgorithmCompanion.shared.fromIdentifier(identifier: algorithmIdentifier)
        let kIv = iv.flatMap { NSDataUtilsKt.toByteArray($0) }
        let kKey = AesKey(rawKey: kRawKey, algorithm: algorithm)
        let encryptedData = try await aes.encrypt(data: kData, key: kKey.dropTypeInfo(), iv: kIv)
        
        return encryptedData.toNSData()
    }
    
    static func decrypt(ivAndEncryptedData: Data, key: Data, algorithmIdentifier: String) async throws -> Data {
        let kData = NSDataUtilsKt.toByteArray(ivAndEncryptedData)
        let kRawKey = NSDataUtilsKt.toByteArray(key)
        let algorithm = try AesAlgorithmCompanion.shared.fromIdentifier(identifier: algorithmIdentifier)
        let kKey = AesKey(rawKey: kRawKey, algorithm: algorithm)
        let decryptedData = try await aes.decrypt(ivAndEncryptedData: kData, key: kKey.dropTypeInfo())
        
        return decryptedData.toNSData()
    }
    
    private static func mapKeyToDictonary(key: AesKey<any AesAlgorithm>) -> [String: Any] {
        return [
            "key": key.rawKey.toNSData(),
            "algorithmIdentifier": key.algorithm.identifier
        ]
    }
}
