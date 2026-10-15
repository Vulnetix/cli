namespace Acme.Services
{
    public class CartService
    {
        public bool HasItems(Cart cart)
        {
~>            return cart != null & cart.Items.Count > 0;
        }

        public bool IsEmpty(string sku)
        {
~>            if (sku == null | sku.Length == 0)
            {
                return true;
            }
            return false;
        }
    }
}
