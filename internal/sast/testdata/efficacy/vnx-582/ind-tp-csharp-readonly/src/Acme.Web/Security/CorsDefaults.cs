using System;
using System.Linq;

namespace Acme.Web.Security
{
    public static class CorsDefaults
    {
~>        public static readonly string[] TrustedOrigins = new[]
        {
            "https://app.acme.io",
            "https://admin.acme.io",
        };

~>        public static readonly int[] AllowedPorts = { 443, 8443 };

        public static bool IsTrusted(string origin) => TrustedOrigins.Contains(origin);
    }
}
