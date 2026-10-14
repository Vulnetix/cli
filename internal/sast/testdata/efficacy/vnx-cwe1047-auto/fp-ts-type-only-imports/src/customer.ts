import { formatId } from './format';
import type {
  Order,
} from './order';

export interface Address { line1: string }
export type Region = 'eu' | 'us';

export class Customer {
  orders: Order[] = [];
  id = formatId('c');
}
