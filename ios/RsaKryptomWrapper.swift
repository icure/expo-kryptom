//
//  ExpoKryptomRsaModule.swift
//  ExpoKryptom
//
//  Created by Clément Vandendaelen on 18/04/2024.
//

import ExpoModulesCore
import Kryptom

public class RsaKryptomWrapper {
    static let shared = RsaKryptomWrapper()
    private let rsa = CryptoServiceKt.defaultCryptoService.rsa
    
    private init() { }
    
    func generateKey(algorithmIdentifier: String, size: Int32, promise: Promise) {
        guard let keySize = determineRsaKeySize(size: size) else {
            promise.reject(Exception(name: "IllegalArgument", description: "Unsupported key size \(size)"))
            return
        }
        
        let algorithm: RsaAlgorithm
        
        do {
            algorithm = try RsaAlgorithmCompanion().fromIdentifier(identifier: algorithmIdentifier)
        } catch let error {
            promise.reject(Exception(name: "IllegalArgument", description: error.localizedDescription))
            return
        }
        
        
        rsa.generateKeyPair(algorithm: algorithm, keySize: keySize) { result, error in
            
            if let generateKeyPairError = error {
                promise.reject(generateKeyPairError)
                return
            }
            
            guard let keyPair = result else {
                fatalError("Result of key generation is null")
            }
            
            guard let castedPrivateKey = keyPair.private_ as? PrivateRsaKey<AnyObject> else {
                fatalError("Cannot cast PrivateRsaKey")
            }
            
            guard let castedPublicKey = keyPair.public_ as? PublicRsaKey<AnyObject> else {
                fatalError("Cannot cast PublicRsaKey")
            }
            
            self.rsa.exportPrivateKeyPkcs8(key: castedPrivateKey) { privateKey, error in
                
                if let exportPrivateKeyError = error {
                    promise.reject(exportPrivateKeyError)
                    return
                }
                
                guard let privateKey = privateKey else {
                    fatalError("Result of exportPrivateKeyPkcs8 is null")
                }
                
                self.rsa.exportPublicKeySpki(key: castedPublicKey) { publicKey, error in
                    
                    if let exportPublicKeyError = error {
                        promise.reject(exportPublicKeyError)
                        return
                    }
                    
                    guard let publicKey = publicKey else {
                        fatalError("Result of exportPublicKeySpki is null")
                    }
                    
                    promise.resolve(
                        [
                            "public": publicKey.toNSData(),
                            "private": privateKey.toNSData(),
                            "algorithmIdentifier": keyPair.algorithm.identifier
                        ]
                    )
                }
            }
        }
    }
}

func determineRsaKeySize(size: Int32) -> RsaServiceKeySize? {
    switch size {
    case 2048:
        return RsaServiceKeySize.rsa2048
    case 4096:
        return RsaServiceKeySize.rsa4096
    default:
        return nil
    }
}
