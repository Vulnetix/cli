using Microsoft.Data.SqlClient;
using Xunit;

namespace Orders.Tests
{
    public class RepositoryTests
    {
        [Fact]
        public void Opens()
        {
            using var conn = new SqlConnection("Server=localhost;Database=OrdersUnit;User Id=sa;Password=Unit-Test-Pw1;");
            Assert.NotNull(conn);
        }
    }
}
