import GameplayKit
import UIKit

final class BoardScene {
    let source = GKARC4RandomSource()

    func roll() -> Int {
        let dice = @@sample:G[K]Ra[n]do[m]Di[s]tr[i]bu[t]io[n][.]d[6]@@()
        return dice.nextInt()
    }

    func shuffleDeck(_ cards: [Card]) -> [Card] {
        source.arrayByShufflingObjects(in: cards) as! [Card]
    }

    func tint() -> UIColor {
        UIColor(red: CGFloat(drand48()), green: CGFloat(drand48()), blue: 0.5, alpha: 1)
    }
}
