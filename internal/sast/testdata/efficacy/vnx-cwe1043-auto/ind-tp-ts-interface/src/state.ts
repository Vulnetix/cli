~>export interface AppState {
  title: string;
  open: boolean;
  user: User;
  profile: Profile;
  settings: Settings;
  cart: Cart;
  orders: Order[];
  wishlist: Wishlist;
  address: Address;
  payment: PaymentMethod;
  theme: Theme;
  session: Session;
  billing: Billing;
  inbox: Message[];
}
