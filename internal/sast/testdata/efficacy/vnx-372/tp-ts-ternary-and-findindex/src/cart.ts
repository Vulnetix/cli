export function inCart(items: string[], sku: string): boolean {
~>  return items.findIndex((i) => i === sku) ? true : false;
}

export function tagged(tags: string[], tag: string): string {
~>  while (tags.indexOf(tag) && tags.length > 0) {
    tags.shift();
  }
  const label = tags.length
~>    ? tags.indexOf(tag) ? 'present' : 'absent'
    : 'empty';
  return label;
}
