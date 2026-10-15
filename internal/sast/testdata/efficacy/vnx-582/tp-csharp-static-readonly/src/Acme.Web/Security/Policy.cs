namespace Acme.Web.Security
{
    public static class Policy
    {
~>        public static readonly string[] TrustedHosts = { "api.example.com", "cdn.example.com" };
~>        public readonly static int[] AllowedPorts = new[] { 80, 443 };
        private static readonly string[] internalNames = { "a" };
    }
}
