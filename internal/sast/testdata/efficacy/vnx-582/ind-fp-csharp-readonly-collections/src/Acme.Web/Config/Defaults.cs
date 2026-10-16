using System;
using System.Collections.Generic;
using System.Collections.Immutable;

namespace Acme.Web.Config
{
    public static class Defaults
    {
        private static readonly string[] hosts = { "api.acme.io" };
        public static readonly IReadOnlyList<string> TrustedHosts = hosts;
        public static readonly ImmutableArray<int> Ports = ImmutableArray.Create(443, 8443);
        public static readonly int[] None = Array.Empty<int>();
        public static string[] GetHosts() => (string[])hosts.Clone();
        public static readonly string Banner = "public static readonly string[] Names = { \"x\" };";
    }
}
