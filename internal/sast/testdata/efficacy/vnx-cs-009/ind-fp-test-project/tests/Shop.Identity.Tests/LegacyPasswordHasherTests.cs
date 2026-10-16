using System;
using System.Security.Cryptography;
using System.Text;
using Shop.Identity.Services;
using Xunit;

namespace Shop.Identity.Tests
{
    public class LegacyPasswordHasherTests
    {
        [Fact]
        public void HashV1_matches_reference_md5()
        {
            using var md5 = MD5.Create();
            var expected = Convert.ToHexString(md5.ComputeHash(Encoding.UTF8.GetBytes("saltpwpepper"))).ToLowerInvariant();

            var hasher = new LegacyPasswordHasher("pepper");

            Assert.Equal(expected, hasher.HashV1("salt", "pw"));
        }

        [Fact]
        public void HashV2_matches_reference_sha1()
        {
            var expected = Convert.ToBase64String(SHA1.HashData(Encoding.UTF8.GetBytes("salt:pw")));
            Assert.Equal(expected, new LegacyPasswordHasher("x").HashV2("salt", "pw"));
        }
    }
}
