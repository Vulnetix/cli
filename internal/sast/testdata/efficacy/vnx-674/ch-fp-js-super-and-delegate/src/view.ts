class View extends Base {
  render(): string {
    return super.render();
  }

  get size(): number {
    return this._size;
  }

  load(id: string) {
    return this.loader.load(id);
  }
}
