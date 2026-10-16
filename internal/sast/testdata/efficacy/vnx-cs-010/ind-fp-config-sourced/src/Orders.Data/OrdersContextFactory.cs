using System;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;

namespace Orders.Data
{
    public sealed class OrdersContextFactory
    {
        private readonly IConfiguration _config;

        public OrdersContextFactory(IConfiguration config) => _config = config;

        public OrdersContext Create()
        {
            var builder = new SqlConnectionStringBuilder(_config.GetConnectionString("Orders"));
            builder.Password = _config["Db:Password"];
            builder.UserID = Environment.GetEnvironmentVariable("ORDERS_DB_USER");

            var options = new DbContextOptionsBuilder<OrdersContext>()
                .UseSqlServer(builder.ConnectionString)
                .Options;
            return new OrdersContext(options);
        }

        public static string ManagedIdentity(string server) =>
            "Server=" + server + ";Database=Orders;Authentication=Active Directory Managed Identity;Encrypt=True;";

        public static string Integrated() =>
            "Data Source=localhost;Initial Catalog=Orders;Integrated Security=True;TrustServerCertificate=True";
    }
}
