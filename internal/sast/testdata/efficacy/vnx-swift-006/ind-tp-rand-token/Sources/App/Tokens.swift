import Foundation

func makeResetToken() -> String {
~>    return String(rand(), radix: 16)
}

func newSalt() -> UInt32 {
~>    let salt = UInt32(random())
    return salt
}
