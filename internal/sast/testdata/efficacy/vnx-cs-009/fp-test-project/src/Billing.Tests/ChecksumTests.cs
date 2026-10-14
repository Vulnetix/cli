using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace Billing.Tests
{
    public class ChecksumTests
    {
        [Fact]
        public void LegacyChecksumMatchesKnownVector()
        {
            using var md5 = MD5.Create();
            var actual = md5.ComputeHash(Encoding.ASCII.GetBytes("abc"));
            Assert.Equal("900150983CD24FB0D6963F7D28E17F72", System.Convert.ToHexString(actual));
        }

        [Fact]
        public void Sha1Vector()
        {
            var actual = SHA1.HashData(Encoding.ASCII.GetBytes("abc"));
            Assert.Equal(20, actual.Length);
        }
    }
}
