// new Turn({ listeningPort: 3478 }) from node-turn has no peer filter
const doc = "--allow-loopback-peers is dangerous";
class Turn {
  constructor(opts) { this.opts = opts; }
}
const t = new Turn({ player: 1 });
module.exports = { doc, t };
