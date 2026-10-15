import GameplayKit

enum OTP {
~>    static let source = GKMersenneTwisterRandomSource(seed: 42)
    static func code() -> Int {
~>        let otp = GKRandomSource.sharedRandom().nextInt(upperBound: 1_000_000)
        return otp
    }
}
