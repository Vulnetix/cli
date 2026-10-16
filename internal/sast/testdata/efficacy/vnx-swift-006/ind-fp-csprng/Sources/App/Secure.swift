import Foundation
import CryptoKit
import Security

func makeToken() -> String {
    let a = arc4random()
    let b = arc4random_uniform(1000)
    var g = SystemRandomNumberGenerator()
    let c = Int.random(in: 0..<100, using: &g)
    var bytes = [UInt8](repeating: 0, count: 32)
    _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
    let key = SymmetricKey(size: .bits256)
    return "\(a)\(b)\(c)\(key.bitCount)"
}
