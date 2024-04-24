import ExpoModulesCore
import Kryptom

public class ExpoKryptomModule: Module {
    public func definition() -> ModuleDefinition {
        Name("ExpoKryptom")
        
        Constants([
            "needExports": true
        ])
        
        AsyncFunction("generateKeyAes") { (size: Int32) in
            guard let keySize = AesKeySize(rawValue: size) else {
                throw Exception(name: "IllegalArgument", description: "Unsupported key size \(size)")
            }
            
            return try await AesKryptomWrapper.generateKey(size: keySize)
        }
        
        AsyncFunction("encryptAes") { (data: Data, key: Data, iv: Data?) in
            return try await AesKryptomWrapper.encrypt(data: data, key: key, iv: iv)
        }
        
        AsyncFunction("decryptAes") { (ivAndEncryptedData: Data, key: Data) in
            return try await AesKryptomWrapper.decrypt(ivAndEncryptedData: ivAndEncryptedData, key: key)
        }
        
        AsyncFunction("generateKeyRsa") { (algorithmIdentifier: String, size: Int32) in
            guard let keySize = RsaKeySize(rawValue: size) else {
                throw Exception(name: "IllegalArgument", description: "Unsupported key size \(size)")
            }
            return try await RsaKryptomWrapper.generateKey(algorithmIdentifier: algorithmIdentifier, size: keySize)
        }
        
        AsyncFunction("decryptRsa") { (data: Data, privateKey: Data, algorithmIdentifier: String) in
            return try await RsaKryptomWrapper.decrypt(data: data, privateKey: privateKey, algorithmIdentifier: algorithmIdentifier)
        }
        
        AsyncFunction("encryptRsa") { (data: Data, publicKey: Data, algorithmIdentifier: String) in
            return try await RsaKryptomWrapper.encrypt(data: data, publicKey: publicKey, algorithmIdentifier: algorithmIdentifier)
        }
        
        AsyncFunction("exportPrivateKeyPkcs8Rsa") { (privateKey: Data, algorithmIdentifier: String) in
            return try await RsaKryptomWrapper.exportPrivateKeyPkcs8(privateKey: privateKey, algorithmIdentifier: algorithmIdentifier)
        }
        
        AsyncFunction("exportPrivateKeyJwkRsa") { (privateKey: Data, algorithmIdentifier: String) in
            return try await RsaKryptomWrapper.exportPrivateKeyJwk(privateKey: privateKey, algorithmIdentifier: algorithmIdentifier)
        }
        
        AsyncFunction("exportPublicKeySpkiRsa") { (publicKey: Data, algorithmIdentifier: String) in
            return try await RsaKryptomWrapper.exportPublicKeySpki(publicKey: publicKey, algorithmIdentifier: algorithmIdentifier)
        }
        
        AsyncFunction("exportPublicKeyJwkRsa") { (publicKey: Data, algorithmIdentifier: String) in
            return try await RsaKryptomWrapper.exportPublicKeyJwk(publicKey: publicKey, algorithmIdentifier: algorithmIdentifier)
        }
        
        AsyncFunction("importPrivateKeyPkcs8Rsa") { (privateKey: Data, algorithmIdentifier: String) in
            return try await RsaKryptomWrapper.importPrivateKeyPkcs8(privateKey: privateKey, algorithmIdentifier: algorithmIdentifier)
        }
        
        AsyncFunction("importPrivateKeyJwkRsa") { (privateKey: ExportPrivateRsaKeyJwk, algorithmIdentifier: String) in
            return try await RsaKryptomWrapper.importPrivateKeyJwk(privateKey: privateKey, algorithmIdentifier: algorithmIdentifier)
        }
        
        AsyncFunction("importPublicKeySpkiRsa") { (publicKey: Data, algorithmIdentifier: String) in
            return try await RsaKryptomWrapper.importPublicKeySpki(publicKey: publicKey, algorithmIdentifier: algorithmIdentifier)
        }
        
        AsyncFunction("importPublicKeyJwkRsa") { (publicKey: ExportPublicRsaKeyJwk, algorithmIdentifier: String) in
            return try await RsaKryptomWrapper.importPublicKeyJwk(publicKey: publicKey, algorithmIdentifier: algorithmIdentifier)
        }
        
        AsyncFunction("importKeyPairRsa") { (privateKey: Data, algorithmIdentifier: String) in
            return try await RsaKryptomWrapper.importKeyPair(privateKey: privateKey, algorithmIdentifier: algorithmIdentifier)
        }
        
        AsyncFunction("signatureRsa") { (data: Data, privateKey: Data, algorithmIdentifier: String) in
            return try await RsaKryptomWrapper.signature(data: data, privateKey: privateKey, algorithmIdentifier: algorithmIdentifier)
        }
        
        AsyncFunction("verifyRsa") { (signature: Data, data: Data, publicKey: Data, algorithmIdentifier: String) in
            return try await RsaKryptomWrapper.verify(signature: signature, data: data, publicKey: publicKey, algorithmIdentifier: algorithmIdentifier)
        }
        
        AsyncFunction("generateKeyHmac") { (algorithmIdentifier: String) in
            return try await HmacKryptomWrapper.generateKey(algorithmIdentifier: algorithmIdentifier)
        }
        
        AsyncFunction("verifyHmac") { (algorithmIdentifier: String, key: Data, signature: Data, data: Data) in
            return try await HmacKryptomWrapper.verify(algorithmIdentifier: algorithmIdentifier, key: key, signature: signature, data: data)
        }
        
        AsyncFunction("signHmac") { (algorithmIdentifier: String, key: Data, data: Data) in
            return try await HmacKryptomWrapper.sign(algorithmIdentifier: algorithmIdentifier, key: key, data: data)
        }
        
        AsyncFunction("sha256") { (data: Data) in
            return try await DigestKryptomWrapper.sha256(data: data)
        }
        
        Function("randomUUID") { () in
            return StrongRandomKryptomWrapper.randomUUID()
        }
        
        Function("randomBytes") { (length: Int32) in
            return StrongRandomKryptomWrapper.randomBytes(length: length)
        }
    }
}
