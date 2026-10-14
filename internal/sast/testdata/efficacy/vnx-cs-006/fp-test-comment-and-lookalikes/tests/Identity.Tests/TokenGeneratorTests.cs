using System;
using Xunit;

namespace Identity.Tests
{
    public class TokenGeneratorTests
    {
        private readonly Random _random = new Random(1234);

        [Fact]
        public void RejectsTamperedToken()
        {
            string token = _random.Next().ToString("x8");
            Assert.False(Validator.IsValid(token));
        }
    }
}
