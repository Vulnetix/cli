using System;
using System.Text;

namespace Auth
{
    public static class ApiKeyFactory
    {
        private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

        public static string CreateApiKey()
        {
~>            return new string(Random.Shared.GetItems(Alphabet.AsSpan(), 40));
        }

        public static string NewSessionId(Random rng)
        {
~>            long value = rng.NextInt64();
            return value.ToString("x16");
        }

        public static string InvitationCode()
        {
            var rng = new Random(Environment.TickCount);
            var sb = new StringBuilder();
            for (var i = 0; i < 8; i++)
            {
~>                sb.Append(Alphabet[rng.Next(Alphabet.Length)]);
            }
            return sb.ToString();
        }
    }
}
