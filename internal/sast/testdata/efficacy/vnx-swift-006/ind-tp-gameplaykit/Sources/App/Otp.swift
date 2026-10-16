import GameplayKit

struct Otp {
    func code() -> Int {
        let src = GKMersenneTwisterRandomSource()
~>        let otp = src.nextInt(upperBound: 1_000_000)
        return otp
    }
    func pin() -> Int {
~>        let pin = GKRandomDistribution(lowestValue: 1000, highestValue: 9999).nextInt()
        return pin
    }
}
