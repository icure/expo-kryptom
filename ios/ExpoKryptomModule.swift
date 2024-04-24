import ExpoModulesCore
import Kryptom

public class ExpoKryptomModule: Module {
    public func definition() -> ModuleDefinition {
        Name("ExpoKryptom")
        
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
            return try await RsaKryptomWrapper.shared.generateKey(algorithmIdentifier: algorithmIdentifier, size: keySize)
        }
        
        AsyncFunction("decryptRsa") { (data: Data, privateKey: Data, algorithmIdentifier: String) in
            return try await RsaKryptomWrapper.shared.decrypt(data: data, privateKey: privateKey, algorithmIdentifier: algorithmIdentifier)
        }
        
        AsyncFunction("encryptRsa") { (data: Data, publicKey: Data, algorithmIdentifier: String) in
            return try await RsaKryptomWrapper.shared.encrypt(data: data, publicKey: publicKey, algorithmIdentifier: algorithmIdentifier)
        }
        
        AsyncFunction("exportPrivateKeyPkcs8") { (privateKey: Data, algorithmIdentifier: String) in
            return try await RsaKryptomWrapper.shared.exportPrivateKeyPkcs8(privateKey: privateKey, algorithmIdentifier: algorithmIdentifier)
        }
        
        AsyncFunction("exportPrivateKeyJwk") { (privateKey: Data, algorithmIdentifier: String) in
            return try await RsaKryptomWrapper.shared.exportPrivateKeyJwk(privateKey: privateKey, algorithmIdentifier: algorithmIdentifier)
        }
        
        AsyncFunction("exportPublicKeySpki") { (publicKey: Data, algorithmIdentifier: String) in
            return try await RsaKryptomWrapper.shared.exportPublicKeySpki(publicKey: publicKey, algorithmIdentifier: algorithmIdentifier)
        }
        
        AsyncFunction("exportPublicKeyJwk") { (publicKey: Data, algorithmIdentifier: String) in
            return try await RsaKryptomWrapper.shared.exportPublicKeyJwk(publicKey: publicKey, algorithmIdentifier: algorithmIdentifier)
        }
        
        AsyncFunction("importPrivateKeyPkcs8") { (privateKey: Data, algorithmIdentifier: String) in
            return try await RsaKryptomWrapper.shared.importPrivateKeyPkcs8(privateKey: privateKey, algorithmIdentifier: algorithmIdentifier)
        }
        
        AsyncFunction("importPrivateKeyJwk") { (privateKey: ExportPrivateRsaKeyJwk, algorithmIdentifier: String) in
            return try await RsaKryptomWrapper.shared.importPrivateKeyJwk(privateKey: privateKey, algorithmIdentifier: algorithmIdentifier)
        }
        
        AsyncFunction("importPublicKeySpki") { (publicKey: Data, algorithmIdentifier: String) in
            return try await RsaKryptomWrapper.shared.importPublicKeySpki(publicKey: publicKey, algorithmIdentifier: algorithmIdentifier)
        }
        
        AsyncFunction("importPublicKeyJwk") { (publicKey: ExportPublicRsaKeyJwk, algorithmIdentifier: String) in
            return try await RsaKryptomWrapper.shared.importPublicKeyJwk(publicKey: publicKey, algorithmIdentifier: algorithmIdentifier)
        }
        
        AsyncFunction("importKeyPair") { (privateKey: Data, algorithmIdentifier: String) in
            return try await RsaKryptomWrapper.shared.importKeyPair(privateKey: privateKey, algorithmIdentifier: algorithmIdentifier)
        }
        
        AsyncFunction("signatureRsa") { (data: Data, privateKey: Data, algorithmIdentifier: String) in
            return try await RsaKryptomWrapper.shared.signature(data: data, privateKey: privateKey, algorithmIdentifier: algorithmIdentifier)
        }
        
        AsyncFunction("verifyRsa") { (signature: Data, data: Data, publicKey: Data, algorithmIdentifier: String) in
            return try await RsaKryptomWrapper.shared.verify(signature: signature, data: data, publicKey: publicKey, algorithmIdentifier: algorithmIdentifier)
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
