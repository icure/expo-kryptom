import ExpoModulesCore
import Kryptom

public class HmacKryptomWrapper {
    static let shared = HmacKryptomWrapper()
    private let hmac = CryptoServiceKt.defaultCryptoService.hmac
    
    private init() { }
    
    func generateKey(algorithmIdentifier: String) async throws -> [String: Any] {
        return mapKeyToDictonary(key: try await hmac.generateKey(algorithm: HmacAlgorithmCompanion.shared.fromIdentifier(identifier: algorithmIdentifier)))
    }
    
    func sign(algorithmIdentifier: String, key: Data, data: Data) async throws -> Data {
        let importedKey = HmacKey(rawKey: NSDataUtilsKt.toByteArray(key), algorithm: HmacAlgorithmCompanion.shared.fromIdentifier(identifier: algorithmIdentifier))
        return try await hmac.sign(data: NSDataUtilsKt.toByteArray(data), key: importedKey.dropTypeInfo()).toNSData()
    }
    
    func verify(algorithmIdentifier: String, key: Data, signature: Data, data: Data) async throws -> Bool {
        let importedKey = HmacKey(rawKey: NSDataUtilsKt.toByteArray(key), algorithm: HmacAlgorithmCompanion.shared.fromIdentifier(identifier: algorithmIdentifier))
        return try await hmac.verify(signature: NSDataUtilsKt.toByteArray(signature), data: NSDataUtilsKt.toByteArray(data), key: importedKey.dropTypeInfo()).boolValue
    }
 
    private func mapKeyToDictonary(key: HmacKey<any HmacAlgorithm>) -> [String: Any] {
        return [
            "key": key.rawKey.toNSData(),
            "algorithmIdentifier": key.algorithm.identifier
        ]
    }
}
