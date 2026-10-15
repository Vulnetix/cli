using System.Collections.Generic;
using System.Collections.Immutable;

namespace Acme.Core
{
    public static class Limits
    {
        public const string Name = "limits";
        public static readonly IReadOnlyList<string> Hosts = new[] { "a", "b" };
        public static readonly ImmutableArray<int> Ports = ImmutableArray.Create(80, 443);
        public static readonly string[] Empty = System.Array.Empty<string>();
        private static readonly int[] Internal = { 1, 2 };
        public static string[] GetNames() => new[] { "x" };
    }
}
