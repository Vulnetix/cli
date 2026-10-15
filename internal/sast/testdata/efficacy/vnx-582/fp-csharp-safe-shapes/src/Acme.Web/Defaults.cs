using System;
using System.Collections.Generic;

namespace Acme.Web
{
    public static class Defaults
    {
        public static readonly IReadOnlyList<string> Hosts = new[] { "a", "b" };
        public static readonly int[] Empty = Array.Empty<int>();
        public const string Name = "acme";
        private static readonly byte[] Salt = { 1, 2 };
        public static string[] GetHosts() => new[] { "a" };
    }
}
