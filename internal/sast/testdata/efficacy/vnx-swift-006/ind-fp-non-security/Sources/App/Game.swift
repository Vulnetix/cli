import Foundation
import GameplayKit

func jitterDelay() -> Double {
    let delay = drand48() * 0.5
    return delay
}
func shuffleDeck(_ cards: [Int]) -> [Int] {
    let source = GKARC4RandomSource()
    let order = source.nextInt(upperBound: cards.count)
    return Array(cards.dropFirst(order))
}
func seedIt() { srand48(42) }
// let token = rand()
let note = "token = rand() is bad"
