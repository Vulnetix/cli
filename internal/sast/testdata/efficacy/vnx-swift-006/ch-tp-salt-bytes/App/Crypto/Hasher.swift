import Foundation

enum Hasher {
    static func hash(_ password: String) -> (Data, Data) {
~>        let salt = Data((0..<16).map { _ in UInt8(rand() % 256) })
        let iv = (0..<16).map { _ in
~>            UInt8(truncatingIfNeeded: random())
        }
        return (salt, Data(iv))
    }
}
