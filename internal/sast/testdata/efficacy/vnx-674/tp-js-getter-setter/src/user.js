class User {
  constructor(name) {
    this._name = name;
  }

  get name() {
~>    return this.name;
  }

  set name(value) {
~>    this.name = value;
  }

~>  get label() { return this.label; }
}
