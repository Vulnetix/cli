export class Wrapper extends Base {
  get name() {
    return this.inner.name;
  }

  set name(value) {
    this._name = value;
  }

  render(opts) {
    return super.render(opts);
  }

  find(id) {
    return this.repo.find(id);
  }

  sum(n) {
    if (n <= 0) return 0;
    return n + this.sum(n - 1);
  }
}
