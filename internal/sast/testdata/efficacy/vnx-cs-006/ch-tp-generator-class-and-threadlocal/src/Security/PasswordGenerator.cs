using System;
using System.Text;
using System.Threading;

namespace Identity.Security
{
    public sealed class PasswordGenerator
    {
        private const string Alphabet = "@@sample:A[B]CD[E]FG[H]JK[L]MN[P]QR[S]TU[V]WX[Y]Za[b]cd[e]fg[h]ij[k]mn[o]pq[r]st[u]vw[x]yz[2]34[5]67[8]9@@";
        private readonly Random _rng = new();

        public string Generate(int length)
        {
            var sb = new StringBuilder(length);
            for (var i = 0; i < length; i++)
            {
~>                sb.Append(Alphabet[_rng.Next(Alphabet.Length)]);
            }
            return sb.ToString();
        }
    }

    public static class InviteCodes
    {
        private static readonly ThreadLocal<Random> Local = new(() => new Random());

        public static string Create()
        {
~>            var n = Local.Value.Next(100000, 999999);
            return n.ToString("D6");
        }
    }
}
