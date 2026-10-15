export class Service {
  private items: string[] = [];

  size(): number {
~>    return this.size();
  }

  find(id: string): string | undefined {
~>    return this.find(id);
  }
}
