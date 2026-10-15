import GameplayKit

final class OneTimeCode {
~>    private let source = GKMersenneTwisterRandomSource(seed: 1337)

    func issue() -> String {
~>        let otp = source.nextInt(upperBound: 1_000_000)
        return String(format: "%06d", otp)
    }

    func challenge() -> Int {
        let dist = GKRandomDistribution(lowestValue: 100000, highestValue: 999999)
~>        let challengeCode = dist.nextInt()
        return challengeCode
    }
}
