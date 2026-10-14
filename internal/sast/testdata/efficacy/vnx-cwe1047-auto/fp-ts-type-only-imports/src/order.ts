import type { Customer } from './customer';
import { type Address, type Region } from './customer';

export interface Order {
  id: string;
  customer: Customer;
  ship: Address;
  region: Region;
}
