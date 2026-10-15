using System;

namespace Shop.Services
{
    public class CartService
    {
        public decimal Total(Cart cart)
        {
            try
            {
                return cart.Customer.Discount.Apply(cart.Sum);
            }
~>            catch (NullReferenceException) when (cart != null)
            {
                return cart.Sum;
            }
        }

        public string Name(User u)
        {
            try { return u.Profile.Name; }
~>            catch (System.NullReferenceException nre) { return string.Empty; }
        }
    }
}
