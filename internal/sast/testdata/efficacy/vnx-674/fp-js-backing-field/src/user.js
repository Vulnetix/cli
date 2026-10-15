class User {
  get name() {
    return this._name;
  }

  set name(value) {
    this._name = value;
  }

  get title() {
    return this.titles[0];
  }

  render(node) {
    return this.renderer.render(node);
  }
}
