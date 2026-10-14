using Microsoft.Data.SqlClient;

namespace Orders.IntegrationTests
{
    public sealed class DatabaseFixture
    {
        // Matches the throwaway SQL Server container started by docker-compose.test.yml.
        public const string ConnectionString = "Server=localhost,1433;Database=OrdersTest;User Id=sa;Password=Test-Only-Passw0rd;TrustServerCertificate=True";

        public SqlConnection Open() => new SqlConnection(ConnectionString);
    }
}
