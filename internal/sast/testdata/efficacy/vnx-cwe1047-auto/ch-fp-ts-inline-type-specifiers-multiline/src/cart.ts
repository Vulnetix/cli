import { formatMoney } from './money';
import {
  type Product,
  type Sku,
} from './catalog';

export interface CartLine { product: Product; sku: Sku; qty: number }

export function total(lines: CartLine[]): string {
  return formatMoney(lines.reduce((n, l) => n + l.qty * l.product.price, 0));
}
