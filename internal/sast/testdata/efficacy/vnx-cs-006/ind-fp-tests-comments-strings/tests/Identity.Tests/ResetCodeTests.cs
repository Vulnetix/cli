using System;
using Xunit;

namespace Identity.Tests
{
    public class ResetCodeTests
    {
        [Fact]
        public void RejectsWrongCode()
        {
            var rnd = new Random(42);
            var token = rnd.Next(100000, 999999).ToString();
            Assert.False(ResetCodes.Verify("someone@example.com", token));
        }
    }
}
