import Foundation
import GameplayKit

struct Board {
    func shuffle(_ tiles: [Int]) -> [Int] {
        let shuffled = GKRandomSource.sharedRandom().arrayByShufflingObjects(in: tiles)
        let jitter = drand48() * 0.2
        let delay = Double(rand() % 10)
        let monkey = random()
        let cacheKey = rand()
        _ = (jitter, delay, monkey, cacheKey)
        return shuffled as? [Int] ?? tiles
    }

    func randomColor() -> Int { Int(rand() % 255) }
    let spin = rand()
}
