export function update(badge: HTMLElement, price: HTMLElement, items: string[], total: number) {
  badge.innerHTML = items.length;
  price.innerHTML = total.toFixed(2);
  badge.innerHTML = String(items.length);
  price.innerHTML = `
    <span class="currency">EUR</span>
  `;
}
