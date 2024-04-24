import ExpoModulesCore
import Kryptom

public struct StrongRandomKryptomWrapper {
    private static let strongRandom = CryptoServiceKt.defaultCryptoService.strongRandom
    
    static func randomBytes(length: Int32) -> Data {
        return strongRandom.randomBytes(length: length).toNSData()
    }
    
    static func randomUUID() -> String {
        return strongRandom.randomUUID()
    }
}
