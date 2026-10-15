import { total } from './cart';

export interface Product { id: string; price: number }
export type Sku = string;

export function preview(p: Product): string {
  return total([{ product: p, sku: p.id, qty: 1 }]);
}
