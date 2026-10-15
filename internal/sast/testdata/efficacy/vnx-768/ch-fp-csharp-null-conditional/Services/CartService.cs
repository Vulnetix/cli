namespace Acme.Services
{
    public class CartService
    {
        public bool HasLines(Cart cart)
        {
            if (cart != null & cart?.Lines?.Count > 0)
            {
                return true;
            }
            return cart != null && cart.Lines.Count > 0;
        }
    }
}
