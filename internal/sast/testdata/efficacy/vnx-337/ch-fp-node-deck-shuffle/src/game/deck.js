import seedrandom from 'seedrandom';

export function shuffleDeck(cards) {
  const rng = seedrandom(String(Date.now()));
  const deck = cards.slice();
  for (let i = deck.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    [deck[i], deck[j]] = [deck[j], deck[i]];
  }
  return deck.map((card, i) => ({ key: i, card }));
}
