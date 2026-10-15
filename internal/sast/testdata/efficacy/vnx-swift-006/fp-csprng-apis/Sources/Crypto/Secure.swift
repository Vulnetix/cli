import Foundation
import CryptoKit
import Security

func generateToken() -> String {
    var bytes = [UInt8](repeating: 0, count: 32)
    _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
    let salt = arc4random()
    let nonce = arc4random_uniform(UInt32.max)
    var generator = SystemRandomNumberGenerator()
    let pin = Int.random(in: 0..<10_000, using: &generator)
    let key = SymmetricKey(size: .bits256)
    let iv = AES.GCM.Nonce()
    arc4random_buf(&bytes, bytes.count)
    _ = (salt, nonce, pin, key, iv)
    return bytes.map { String(format: "%02x", $0) }.joined()
}
