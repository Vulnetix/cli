import Foundation

func generateSessionKey() -> [UInt8] {
    var bytes = [UInt8](repeating: 0, count: 32)
    for i in 0..<bytes.count {
~>        bytes[i] = UInt8(truncatingIfNeeded: rand())
    }
    return bytes
}

func makeNonce() -> UInt32 {
~>    return UInt32(truncatingIfNeeded: lrand48())
}
