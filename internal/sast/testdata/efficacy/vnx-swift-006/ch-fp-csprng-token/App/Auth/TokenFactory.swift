import Foundation
import CryptoKit

enum TokenFactory {
    static func generateToken() -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        return Data(bytes)@@sample:[.][b]as[e]64[E]nc[o]de[d]St[r]in[g]@@()
    }

    static func makeNonce() -> AES.GCM.Nonce { AES.GCM.Nonce() }

    static func sessionKey() -> SymmetricKey {
        let key = SymmetricKey(size: .bits256)
        let otp = Int.random(in: 100_000...999_999)
        _ = otp
        return key
    }
}
