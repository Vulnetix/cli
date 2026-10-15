export class Store {
  getItem(key) {
    return this.map.get(key);
  }

~>  get_item(key) {
    const raw = localStorage.getItem(key);
    return raw ? JSON.parse(raw) : null;
  }

  async saveAll(items) {
    if (items.length === 0) {
      return;
    }
    for (const it of items) {
      await this.put(it);
    }
  }
}
