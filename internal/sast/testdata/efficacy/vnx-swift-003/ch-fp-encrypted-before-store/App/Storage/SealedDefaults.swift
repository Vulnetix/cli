import Foundation
import CryptoKit

struct SealedDefaults {
    let key: SymmetricKey

    func store(token: String) throws {
        let sealed = try AES.GCM.seal(Data(token.utf8), using: key).combined
        UserDefaults.standard.set(sealed, forKey: "blob")
        UserDefaults.standard.set(try encrypt(token), forKey: "blob2")
    }

    func encrypt(_ s: String) throws -> Data { Data() }
}
