export class Profile {
  constructor(name, avatar) {
    this._name = name;
    this._avatar = avatar;
  }

  get name() {
~>    return this.name;
  }

  set name(value) {
~>    this.name = value;
  }

  get avatar() {
    return this._avatar;
  }
}
