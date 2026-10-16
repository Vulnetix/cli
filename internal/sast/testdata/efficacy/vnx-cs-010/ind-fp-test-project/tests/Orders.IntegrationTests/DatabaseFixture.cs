using System;
using Microsoft.Data.SqlClient;

namespace Orders.IntegrationTests
{
    public sealed class DatabaseFixture : IDisposable
    {
        // Matches the throwaway SQL Server container started by docker-compose.test.yml.
        public const string ConnectionString = "Server=localhost,14333;Database=OrdersTest;User Id=sa;Password=Integration-Test-1!;TrustServerCertificate=True";

        public SqlConnection Connection { get; }

        public DatabaseFixture()
        {
            Connection = new SqlConnection(ConnectionString);
            Connection.Open();
        }

        public void Dispose() => Connection.Dispose();
    }
}
