using System;

namespace Acme.Services
{
    public class Lookup
    {
        public string Name(Customer c)
        {
            try
            {
                return c.Profile.DisplayName;
            }
~>            catch (Exception ex) when (ex is NullReferenceException)
            {
                return "";
            }
        }

        public string Safe(Customer c)
        {
            try
            {
                return c?.Profile?.DisplayName ?? "";
            }
            catch (Exception ex) when (ex is TimeoutException)
            {
                return "";
            }
        }
    }
}
