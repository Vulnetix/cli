using System;

namespace Acme.Auth
{
    public class CallerPolicy
    {
        public bool Allow(object caller)
        {
~>            if (caller.GetType().Name == "TrustedCaller")
                return true;
~>            if (caller.GetType().FullName.Equals("Acme.Internal.SystemCaller"))
                return true;
            return false;
        }

        public int Weight(object handler)
        {
~>            return handler.GetType().Name switch
            {
                "AdminHandler" => 100,
                "UserHandler" => 10,
                _ => 0,
            };
        }
    }
}
