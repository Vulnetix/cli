using System;

namespace Acme.Auth
{
    public class Policy
    {
        public bool IsPrivileged(object principal)
        {
~>            if (principal.GetType().Name.Equals("AdminPrincipal", StringComparison.Ordinal))
                return true;
~>            if (string.Equals(principal.GetType().FullName, "Acme.Auth.Root"))
                return true;
~>            return principal.GetType().Name != "Guest";
        }
    }
}
