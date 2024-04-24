import ExpoModulesCore
import Kryptom

public struct DigestKryptomWrapper {
    private static let digest = CryptoServiceKt.defaultCryptoService.digest

    static func sha256(data: Data) async throws -> Data {
        return try await digest.sha256(data: NSDataUtilsKt.toByteArray(data)).toNSData()
    }
}
