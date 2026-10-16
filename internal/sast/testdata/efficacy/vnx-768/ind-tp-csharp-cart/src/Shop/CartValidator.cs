using System;

namespace Shop
{
    public class CartValidator
    {
        public bool HasItems(Cart cart)
        {
~>            return cart != null & cart.Items.Count > 0;
        }

        public bool IsAnonymous(Session session)
        {
~>            if (session == null | session.UserId == Guid.Empty)
            {
                return true;
            }
            return false;
        }
    }
}
