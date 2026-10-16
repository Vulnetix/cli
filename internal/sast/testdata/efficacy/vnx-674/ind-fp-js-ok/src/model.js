class Model {
  get name() {
    return this._name;
  }
  set name(v) {
    this._name = v;
  }
  get id() {
    return this.state.id;
  }
}
// get x() { return this.x; }
const s = "set y(v) { this.y = v; }";
module.exports = Model;
