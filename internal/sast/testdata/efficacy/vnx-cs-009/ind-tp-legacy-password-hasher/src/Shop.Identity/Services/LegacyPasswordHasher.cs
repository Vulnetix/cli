using System;
using System.Security.Cryptography;
using System.Text;

namespace Shop.Identity.Services
{
    /// <summary>Verifies passwords imported from the 2014 storefront database.</summary>
    public sealed class LegacyPasswordHasher
    {
        private readonly string _pepper;

        public LegacyPasswordHasher(string pepper)
        {
            _pepper = pepper ?? throw new ArgumentNullException(nameof(pepper));
        }

        public string HashV1(string salt, string password)
        {
~>            using var md5 = MD5.Create();
            var bytes = md5.ComputeHash(Encoding.UTF8.GetBytes(salt + password + _pepper));
            return Convert.ToHexString(bytes).ToLowerInvariant();
        }

        public string HashV2(string salt, string password)
        {
            var input = Encoding.UTF8.GetBytes($"{salt}:{password}");
~>            var digest = SHA1.HashData(input);
            return Convert.ToBase64String(digest);
        }

        public bool VerifyV0(string stored, string password)
        {
~>            using (var provider = new SHA1CryptoServiceProvider())
            {
                var computed = provider.ComputeHash(Encoding.Unicode.GetBytes(password));
                return CryptographicOperations.FixedTimeEquals(computed, Convert.FromBase64String(stored));
            }
        }
    }
}
