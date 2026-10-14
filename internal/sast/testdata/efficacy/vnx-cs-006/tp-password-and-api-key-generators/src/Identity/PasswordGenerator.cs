using System;
using System.Linq;
using System.Text;

namespace Identity
{
    public static class PasswordGenerator
    {
        private const string Chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
        private static readonly Random Rng = new Random();

        public static string GeneratePassword(int length)
        {
            var sb = new StringBuilder();
            for (int i = 0; i < length; i++)
            {
~>                sb.Append(Chars[Rng.Next(Chars.Length)]);
            }
            return sb.ToString();
        }

        public static string NewApiKey()
        {
~>            return new string(Enumerable.Range(0, 32).Select(_ => Chars[Random.Shared.Next(Chars.Length)]).ToArray());
        }

        public static string CreateSecret(Random random)
        {
~>            return new string(random.GetItems(Chars.ToCharArray(), 40));
        }
    }
}
