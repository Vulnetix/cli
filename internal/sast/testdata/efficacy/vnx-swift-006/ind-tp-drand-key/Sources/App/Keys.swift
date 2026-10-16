import Foundation

func generateSessionKey() -> [UInt8] {
    var bytes = [UInt8](repeating: 0, count: 16)
    for i in 0..<bytes.count {
~>        bytes[i] = UInt8(lrand48() & 0xff)
    }
    return bytes
}
