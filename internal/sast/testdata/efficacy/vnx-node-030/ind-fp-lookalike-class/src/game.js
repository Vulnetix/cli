class Turn {
  constructor(player) { this.player = player; }
  next() { return this.player + 1; }
}
const t = new Turn(1);
console.log(t.next());
