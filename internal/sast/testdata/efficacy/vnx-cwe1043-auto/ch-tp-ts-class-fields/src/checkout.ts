import { Cart, Customer, Address, PaymentMethod, Promotion, TaxQuote, ShippingQuote, Store, Currency, Session, RiskScore } from './types';

~>export class CheckoutState {
  cart: Cart;
  customer: Customer | null = null;
  billing?: Address;
  shipping?: Address;
  payment!: PaymentMethod;
  promotions: Promotion[] = [];
  tax: TaxQuote | undefined;
  shippingQuote: ShippingQuote | undefined;
  private readonly store: Store;
  currency: Currency;
  session: Session;
  risk: RiskScore;
  step: 'cart' | 'address' | 'pay' = 'cart';

  constructor(cart: Cart, store: Store) {
    this.cart = cart;
    this.store = store;
  }
}
