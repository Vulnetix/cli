namespace Shop.Api.Services;

public class CartService
{
    public decimal Total(Cart cart)
    {
        try
        {
            return cart.Customer.Discount.Apply(cart.Subtotal);
        }
~>        catch (NullReferenceException)
        {
            return cart?.Subtotal ?? 0m;
        }
    }

    public string Owner(Cart cart)
    {
~>        try { return cart.Customer.Name; } catch (System.NullReferenceException ex) { return ""; }
    }
}
