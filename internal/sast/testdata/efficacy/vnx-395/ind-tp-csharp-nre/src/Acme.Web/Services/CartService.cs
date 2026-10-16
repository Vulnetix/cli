using System;

namespace Acme.Web.Services
{
    public class CartService
    {
        public decimal Subtotal(Cart cart)
        {
            try
            {
                return cart.Customer.Discount.Apply(cart.Total);
            }
~>            catch (NullReferenceException)
            {
                return cart?.Total ?? 0m;
            }
        }

        public string CouponCode(Cart cart)
        {
            try
            {
                return cart.Coupon.Code.ToUpperInvariant();
            }
~>            catch (System.NullReferenceException ex)
            {
                return string.Empty;
            }
        }
    }
}
