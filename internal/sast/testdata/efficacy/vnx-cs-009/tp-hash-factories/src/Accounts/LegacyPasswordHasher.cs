using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Shop.Accounts
{
    public sealed class LegacyPasswordHasher
    {
        public string Hash(string password, string salt)
        {
~>            using var md5 = MD5.Create();
            var bytes = md5.ComputeHash(Encoding.UTF8.GetBytes(salt + password));
            return Convert.ToHexString(bytes);
        }

        public byte[] HashToken(string token)
        {
~>            return SHA1.HashData(Encoding.UTF8.GetBytes(token));
        }

        public async Task<byte[]> HashFileAsync(Stream input)
        {
~>            return await SHA1.HashDataAsync(input);
        }

        public string Fingerprint(byte[] apiKey)
        {
~>            byte[] digest = System.Security.Cryptography.MD5.HashData(apiKey);
            return Convert.ToBase64String(digest);
        }

        public bool Verify(string password, string salt, string expected)
        {
            HashAlgorithm algo = expected.Length == 32
~>                ? MD5.Create()
                : SHA256.Create();
            var actual = algo.ComputeHash(Encoding.UTF8.GetBytes(salt + password));
            return Convert.ToHexString(actual) == expected;
        }

        public byte[] HashSession(byte[] sessionId)
        {
~>            return global::System.Security.Cryptography.SHA1
                .HashData(sessionId);
        }

        public byte[] Seal(byte[] value)
        {
~>            using (var sha = SHA1.Create())
            {
                return sha.ComputeHash(value);
            }
        }
    }
}
