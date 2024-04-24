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

public class RsaKryptomWrapper {
    static let shared = RsaKryptomWrapper()
    private let rsa = CryptoServiceKt.defaultCryptoService.rsa
    
    private init() { }
    
    func generateKey(algorithmIdentifier: String, size: RsaKeySize) async throws -> [String: Any] {
        let algorithm: RsaAlgorithm = try RsaAlgorithmCompanion.shared.fromIdentifier(identifier: algorithmIdentifier)
        
        let generatedKeyPair = try await rsa.generateKeyPair(algorithm: algorithm, keySize: size.toRsaServiceKeySize())
                
        return mapKeyPairToDictonary(keyPair: generatedKeyPair)
    }
    
    func decrypt(data: Data, privateKey: Data, algorithmIdentifier: String) async throws -> Data {
        let algorithm = try RsaAlgorithmRsaEncryptionAlgorithmCompanion.shared.fromIdentifier(identifier: algorithmIdentifier)
                
        let mappedRawKey = NSDataUtilsKt.toByteArray(privateKey)
        let mappedPrivateRsaKey = PrivateRsaKey(rawKey: mappedRawKey, algorithm: algorithm)
        
        let toDecrypt = NSDataUtilsKt.toByteArray(data)
        let decryptedData = try await rsa.decrypt(data: toDecrypt, privateKey: mappedPrivateRsaKey)
        return decryptedData.toNSData()
    }
    
    func encrypt(data: Data, publicKey: Data, algorithmIdentifier: String) async throws -> Data {
        let algorithm = try RsaAlgorithmRsaEncryptionAlgorithmCompanion.shared.fromIdentifier(identifier: algorithmIdentifier)
                
        let mappedRawKey = NSDataUtilsKt.toByteArray(publicKey)
        let mappedPublicRsaKey = PublicRsaKey(rawKey: mappedRawKey, algorithm: algorithm)
        
        return try await rsa.encrypt(data: NSDataUtilsKt.toByteArray(data), publicKey: mappedPublicRsaKey).toNSData()
    }
    
    func exportPrivateKeyPkcs8(privateKey: Data, algorithmIdentifier: String) async throws -> Data {
        let algorithm = try RsaAlgorithmRsaEncryptionAlgorithmCompanion.shared.fromIdentifier(identifier: algorithmIdentifier)
        let mappedRawKey = NSDataUtilsKt.toByteArray(privateKey)
        let loadedPrivateKey = PrivateRsaKey(rawKey: mappedRawKey, algorithm: algorithm).dropTypeInfo()
        
        return try await rsa.exportPrivateKeyPkcs8(key: loadedPrivateKey).toNSData()
    }
    
    func exportPrivateKeyJwk(privateKey: Data, algorithmIdentifier: String) async throws -> ExportPrivateRsaKeyJwk {
        let algorithm = try RsaAlgorithmRsaEncryptionAlgorithmCompanion.shared.fromIdentifier(identifier: algorithmIdentifier)
        let mappedRawKey = NSDataUtilsKt.toByteArray(privateKey)
        let loadedPrivateKey = PrivateRsaKey(rawKey: mappedRawKey, algorithm: algorithm).dropTypeInfo()
        
        let exportedPrivateKey = try await rsa.exportPrivateKeyJwk(key: loadedPrivateKey)
        
        return ExportPrivateRsaKeyJwk(
            alg: Field(wrappedValue: exportedPrivateKey.alg),
            d: Field(wrappedValue: exportedPrivateKey.d),
            dp: Field(wrappedValue: exportedPrivateKey.dp),
            dq: Field(wrappedValue: exportedPrivateKey.dq),
            e: Field(wrappedValue: exportedPrivateKey.e),
            ext: Field(wrappedValue: exportedPrivateKey.ext),
            key_ops: Field(wrappedValue: Array(exportedPrivateKey.key_ops)),
            n: Field(wrappedValue: exportedPrivateKey.n),
            p: Field(wrappedValue: exportedPrivateKey.p),
            q: Field(wrappedValue: exportedPrivateKey.q),
            qi: Field(wrappedValue: exportedPrivateKey.qi)
        )
    }
    
    func exportPublicKeySpki(publicKey: Data, algorithmIdentifier: String) async throws -> Data {
        let algorithm = try RsaAlgorithmRsaEncryptionAlgorithmCompanion.shared.fromIdentifier(identifier: algorithmIdentifier)
        let mappedPublicKey = NSDataUtilsKt.toByteArray(publicKey)
        let loadedPublicKey = PublicRsaKey(rawKey: mappedPublicKey, algorithm: algorithm).dropTypeInfo()
        
        return try await rsa.exportPublicKeySpki(key: loadedPublicKey).toNSData()
    }
    
    func exportPublicKeyJwk(publicKey: Data, algorithmIdentifier: String) async throws -> ExportPublicRsaKeyJwk {
        let algorithm = try RsaAlgorithmRsaEncryptionAlgorithmCompanion.shared.fromIdentifier(identifier: algorithmIdentifier)
        let mappedPublicKey = NSDataUtilsKt.toByteArray(publicKey)
        let loadedPublicKey = PublicRsaKey(rawKey: mappedPublicKey, algorithm: algorithm).dropTypeInfo()
        
        let exportedPublicKey = try await rsa.exportPublicKeyJwk(key: loadedPublicKey)
        
        return ExportPublicRsaKeyJwk(
            alg: Field(wrappedValue: exportedPublicKey.alg),
            e: Field(wrappedValue: exportedPublicKey.e),
            ext: Field(wrappedValue: exportedPublicKey.ext),
            key_ops: Field(wrappedValue: Array(exportedPublicKey.key_ops)),
            n: Field(wrappedValue: exportedPublicKey.n)
        )
    }
    
    func importPrivateKeyPkcs8(privateKey: Data, algorithmIdentifier: String) async throws -> Data {
        let algorithm = try RsaAlgorithmCompanion.shared.fromIdentifier(identifier: algorithmIdentifier)
        let importedPrivateKey = try await rsa.loadPrivateKeyPkcs8(algorithm: algorithm, privateKeyPkcs8: NSDataUtilsKt.toByteArray(privateKey))
        
        return importedPrivateKey.rawKey.toNSData()
    }
    
    func importPrivateKeyJwk(privateKey: ExportPrivateRsaKeyJwk, algorithmIdentifier: String) async throws -> Data {
        let algorithm = try RsaAlgorithmCompanion.shared.fromIdentifier(identifier: algorithmIdentifier)
        let importedPrivateKey = try await rsa.loadPrivateKeyJwk(algorithm: algorithm, privateKeyJwk: privateKey.toPrivateRsaKeyJwk())
        
        return importedPrivateKey.rawKey.toNSData()
    }
    
    func importPublicKeySpki(publicKey: Data, algorithmIdentifier: String) async throws -> Data {
        let algorithm = try RsaAlgorithmCompanion.shared.fromIdentifier(identifier: algorithmIdentifier)
        let importedPublicKey = try await rsa.loadPublicKeySpki(algorithm: algorithm, publicKeySpki: NSDataUtilsKt.toByteArray(publicKey))
        
        return importedPublicKey.rawKey.toNSData()
    }
    
    func importPublicKeyJwk(publicKey: ExportPublicRsaKeyJwk, algorithmIdentifier: String) async throws -> Data {
        let algorithm = try RsaAlgorithmCompanion.shared.fromIdentifier(identifier: algorithmIdentifier)
        let importedPublicKey = try await rsa.loadPublicKeyJwk(algorithm: algorithm, publicKeyJwk: publicKey.toPublicRsaKeyJwk())
        
        return importedPublicKey.rawKey.toNSData()
    }
    
    func importKeyPair(privateKey: Data, algorithmIdentifier: String) async throws -> [String: Any] {
        let algorithm = try RsaAlgorithmCompanion.shared.fromIdentifier(identifier: algorithmIdentifier)
        let importedKeyPair = try await rsa.loadKeyPairPkcs8(algorithm: algorithm, privateKeyPkcs8: NSDataUtilsKt.toByteArray(privateKey))
        
        return mapKeyPairToDictonary(keyPair: importedKeyPair)
    }
    
    func verify(signature: Data, data: Data, publicKey: Data, algorithmIdentifier: String) async throws -> Bool {
        let algorithm = try RsaAlgorithmRsaSignatureAlgorithmCompanion.shared.fromIdentifier(identifier: algorithmIdentifier)
        let mappedRawKey = NSDataUtilsKt.toByteArray(publicKey)
        let mappedPublicRsaKey = PublicRsaKey(rawKey: mappedRawKey, algorithm: algorithm)
        
        return try await rsa.verifySignature(signature: NSDataUtilsKt.toByteArray(signature), data: NSDataUtilsKt.toByteArray(data), publicKey: mappedPublicRsaKey).boolValue
    }
    
    func signature(data: Data, privateKey: Data, algorithmIdentifier: String) async throws -> Data {
        let algorithm = try RsaAlgorithmRsaSignatureAlgorithmCompanion.shared.fromIdentifier(identifier: algorithmIdentifier)
        let mappedRawKey = NSDataUtilsKt.toByteArray(privateKey)
        let mappedPrivateRsaKey = PrivateRsaKey(rawKey: mappedRawKey, algorithm: algorithm)
        
        return try await rsa.sign(data: NSDataUtilsKt.toByteArray(data), privateKey: mappedPrivateRsaKey).toNSData()
    }
    
    private func mapKeyPairToDictonary(keyPair: RsaKeypair<RsaAlgorithm>) -> [String: Any] {
        return [
            "private": keyPair.private_.rawKey.toNSData(),
            "public": keyPair.public_.rawKey.toNSData(),
            "algorithmIdentifier": keyPair.algorithm.identifier
        ]
    }
}
