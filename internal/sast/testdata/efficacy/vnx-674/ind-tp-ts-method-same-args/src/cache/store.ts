export class Store {
  private readonly data = new Map<string, string>();

  fetch(key: string): string | undefined {
~>    return this.fetch(key);
  }

  has(key: string): boolean {
    return this.data.has(key);
  }
}
