using System;

namespace Shop
{
    public class SafeCartValidator
    {
        public bool HasItems(Cart cart)
        {
            return cart?.Items.Count > 0;
        }

        public bool Ready(Cart cart, Inventory inventory)
        {
            // cart != null & cart.Items.Count > 0 would throw on null
            string hint = "use && not &: x != null & x.Foo()";
            return cart != null && cart.Items.Count > 0 && hint.Length > 0;
        }

        public bool BothPresent(Cart cart, Inventory inventory)
        {
            return cart != null & inventory.IsOpen;
        }
    }
}
