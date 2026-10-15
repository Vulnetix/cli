export class Store {
  private slots: Array<string | null> = [];

  clear(idx: number): void {
    // meant to empty the slot
~>    this.slots[idx] === null;
  }
}
