namespace Acme.Services
{
    public class NameService
    {
        public bool IsBlank(string name)
        {
~>            if (null == name | name.Trim().Length == 0)
            {
                return true;
            }
            return false;
        }

        public bool HasItems(Order order)
        {
~>            return order.Lines != null &
                   order.Lines.Count > 0;
        }
    }
}
