namespace Acme.Services
{
    public class Report
    {
        // if (cart != null & cart.Items.Count > 0) is wrong, use &&
        private const string Hint = "x != null & x.Count > 0";

        public bool Any(Cart cart)
        {
            return cart != null & cart?.Items != null;
        }
    }
}
