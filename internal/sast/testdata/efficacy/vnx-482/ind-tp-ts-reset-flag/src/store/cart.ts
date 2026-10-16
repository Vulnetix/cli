export class CartStore {
  private dirty = false;
  private items: string[] = [];

  clear(): void {
    this.items = [];
~>    this.dirty == false;
  }
}
