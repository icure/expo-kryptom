//
//  ExpoKryptomRsaModule.swift
//  ExpoKryptom
//
//  Created by Clément Vandendaelen on 18/04/2024.
//

import ExpoModulesCore
import Kryptom

enum RsaKeySize: Int32 {
    case rsa2048 = 2048
    case rsa4096 = 4096
    
    
    func toRsaServiceKeySize() -> RsaServiceKeySize {
        return switch self {
        case .rsa2048:
                .rsa2048
        case .rsa4096:
                .rsa4096
        }
    }
}

public struct RsaKryptomWrapper {
    private static let rsa = CryptoServiceKt.defaultCryptoService.rsa
    
    static func generateKey(algorithmIdentifier: String, size: RsaKeySize) async throws -> [String: Any] {
        let algorithm: RsaAlgorithm = try RsaAlgorithmCompanion.shared.fromIdentifier(identifier: algorithmIdentifier)
        
        let generatedKeyPair = try await rsa.generateKeyPair(algorithm: algorithm, keySize: size.toRsaServiceKeySize())
                
        return mapKeyPairToDictonary(keyPair: generatedKeyPair)
    }
    
    static func decrypt(data: Data, privateKey: Data, algorithmIdentifier: String) async throws -> Data {
        let algorithm = try RsaAlgorithmRsaEncryptionAlgorithmCompanion.shared.fromIdentifier(identifier: algorithmIdentifier)
                
        let mappedRawKey = NSDataUtilsKt.toByteArray(privateKey)
        let mappedPrivateRsaKey = PrivateRsaKey(rawKey: mappedRawKey, algorithm: algorithm)
        
        let toDecrypt = NSDataUtilsKt.toByteArray(data)
        let decryptedData = try await rsa.decrypt(data: toDecrypt, privateKey: mappedPrivateRsaKey)
        return decryptedData.toNSData()
    }
    
    static func encrypt(data: Data, publicKey: Data, algorithmIdentifier: String) async throws -> Data {
        let algorithm = try RsaAlgorithmRsaEncryptionAlgorithmCompanion.shared.fromIdentifier(identifier: algorithmIdentifier)
                
        let mappedRawKey = NSDataUtilsKt.toByteArray(publicKey)
        let mappedPublicRsaKey = PublicRsaKey(rawKey: mappedRawKey, algorithm: algorithm)
        
        return try await rsa.encrypt(data: NSDataUtilsKt.toByteArray(data), publicKey: mappedPublicRsaKey).toNSData()
    }
    
    static func exportPrivateKeyPkcs8(privateKey: Data, algorithmIdentifier: String) async throws -> Data {
        let algorithm = try RsaAlgorithmCompanion.shared.fromIdentifier(identifier: algorithmIdentifier)
        let mappedRawKey = NSDataUtilsKt.toByteArray(privateKey)
        let loadedPrivateKey = PrivateRsaKey(rawKey: mappedRawKey, algorithm: algorithm).dropTypeInfo()
        
        return try await rsa.exportPrivateKeyPkcs8(key: loadedPrivateKey).toNSData()
    }
    
    static func exportPrivateKeyJwk(privateKey: Data, algorithmIdentifier: String) async throws -> ExportPrivateRsaKeyJwk {
        let algorithm = try RsaAlgorithmCompanion.shared.fromIdentifier(identifier: algorithmIdentifier)
        let mappedRawKey = NSDataUtilsKt.toByteArray(privateKey)
        let loadedPrivateKey = PrivateRsaKey(rawKey: mappedRawKey, algorithm: algorithm).dropTypeInfo()
        
        let exportedPrivateKey = try await rsa.exportPrivateKeyJwk(key: loadedPrivateKey)
        
        return ExportPrivateRsaKeyJwk.fromPrivateRsaKeyJwk(privateKey: exportedPrivateKey)
    }
    
    static func exportPublicKeySpki(publicKey: Data, algorithmIdentifier: String) async throws -> Data {
        let algorithm = try RsaAlgorithmCompanion.shared.fromIdentifier(identifier: algorithmIdentifier)
        let mappedPublicKey = NSDataUtilsKt.toByteArray(publicKey)
        let loadedPublicKey = PublicRsaKey(rawKey: mappedPublicKey, algorithm: algorithm).dropTypeInfo()
        
        return try await rsa.exportPublicKeySpki(key: loadedPublicKey).toNSData()
    }
    
    static func exportPublicKeyJwk(publicKey: Data, algorithmIdentifier: String) async throws -> ExportPublicRsaKeyJwk {
        let algorithm = try RsaAlgorithmCompanion.shared.fromIdentifier(identifier: algorithmIdentifier)
        let mappedPublicKey = NSDataUtilsKt.toByteArray(publicKey)
        let loadedPublicKey = PublicRsaKey(rawKey: mappedPublicKey, algorithm: algorithm).dropTypeInfo()
        
        let exportedPublicKey = try await rsa.exportPublicKeyJwk(key: loadedPublicKey)
        
        return ExportPublicRsaKeyJwk.fromPublicKeyRsaKeyJwk(publicKey: exportedPublicKey)
    }
    
    static func importPrivateKeyPkcs8(privateKey: Data, algorithmIdentifier: String) async throws -> [String: Any] {
        let algorithm = try RsaAlgorithmCompanion.shared.fromIdentifier(identifier: algorithmIdentifier)
        let importedPrivateKey = try await rsa.loadPrivateKeyPkcs8(algorithm: algorithm, privateKeyPkcs8: NSDataUtilsKt.toByteArray(privateKey))
        
        return mapPrivateKeyToDictionnary(privateKey: importedPrivateKey)
    }
    
    static func importPrivateKeyJwk(privateKey: ExportPrivateRsaKeyJwk) async throws -> [String: Any] {
        let algorithm = try RsaAlgorithmCompanion.shared.fromJwkIdentifier(jwkIdentifier: privateKey.alg)
        let importedPrivateKey = try await rsa.loadPrivateKeyJwk(algorithm: algorithm, privateKeyJwk: privateKey.toPrivateRsaKeyJwk())
        
        return mapPrivateKeyToDictionnary(privateKey: importedPrivateKey)
    }
    
    static func importPublicKeySpki(publicKey: Data, algorithmIdentifier: String) async throws -> [String: Any] {
        let algorithm = try RsaAlgorithmCompanion.shared.fromIdentifier(identifier: algorithmIdentifier)
        let importedPublicKey = try await rsa.loadPublicKeySpki(algorithm: algorithm, publicKeySpki: NSDataUtilsKt.toByteArray(publicKey))
        
        return mapPublicKeyToDictionnary(publicKey: importedPublicKey)
    }
    
    static func importPublicKeyJwk(publicKey: ExportPublicRsaKeyJwk) async throws -> [String: Any] {
        let algorithm = try RsaAlgorithmCompanion.shared.fromJwkIdentifier(jwkIdentifier: publicKey.alg)
        let importedPublicKey = try await rsa.loadPublicKeyJwk(algorithm: algorithm, publicKeyJwk: publicKey.toPublicRsaKeyJwk())
        
        return mapPublicKeyToDictionnary(publicKey: importedPublicKey)
    }
    
    static func importKeyPair(privateKey: Data, algorithmIdentifier: String) async throws -> [String: Any] {
        let algorithm = try RsaAlgorithmCompanion.shared.fromIdentifier(identifier: algorithmIdentifier)
        let importedKeyPair = try await rsa.loadKeyPairPkcs8(algorithm: algorithm, privateKeyPkcs8: NSDataUtilsKt.toByteArray(privateKey))
        
        return mapKeyPairToDictonary(keyPair: importedKeyPair)
    }
    
    static func verify(signature: Data, data: Data, publicKey: Data, algorithmIdentifier: String) async throws -> Bool {
        let algorithm = try RsaAlgorithmRsaSignatureAlgorithmCompanion.shared.fromIdentifier(identifier: algorithmIdentifier)
        let mappedRawKey = NSDataUtilsKt.toByteArray(publicKey)
        let mappedPublicRsaKey = PublicRsaKey(rawKey: mappedRawKey, algorithm: algorithm)
        
        return try await rsa.verifySignature(signature: NSDataUtilsKt.toByteArray(signature), data: NSDataUtilsKt.toByteArray(data), publicKey: mappedPublicRsaKey).boolValue
    }
    
    static func signature(data: Data, privateKey: Data, algorithmIdentifier: String) async throws -> Data {
        let algorithm = try RsaAlgorithmRsaSignatureAlgorithmCompanion.shared.fromIdentifier(identifier: algorithmIdentifier)
        let mappedRawKey = NSDataUtilsKt.toByteArray(privateKey)
        let mappedPrivateRsaKey = PrivateRsaKey(rawKey: mappedRawKey, algorithm: algorithm)
        
        return try await rsa.sign(data: NSDataUtilsKt.toByteArray(data), privateKey: mappedPrivateRsaKey).toNSData()
    }
    
    private static func mapKeyPairToDictonary(keyPair: RsaKeypair<RsaAlgorithm>) -> [String: Any] {
        return [
            "privateKey": keyPair.private_.rawKey.toNSData(),
            "publicKey": keyPair.public_.rawKey.toNSData(),
            "algorithmIdentifier": keyPair.algorithm.identifier
        ]
    }
    
    private static func mapPublicKeyToDictionnary(publicKey: PublicRsaKey<RsaAlgorithm>) -> [String: Any] {
        return [
            "publicKey": publicKey.rawKey.toNSData(),
            "algorithmIdentifier": publicKey.algorithm.identifier
        ]
    }
    
    private static func mapPrivateKeyToDictionnary(privateKey: PrivateRsaKey<RsaAlgorithm>) -> [String: Any] {
        return [
            "privateKey": privateKey.rawKey.toNSData(),
            "algorithmIdentifier": privateKey.algorithm.identifier
        ]
    }
}
