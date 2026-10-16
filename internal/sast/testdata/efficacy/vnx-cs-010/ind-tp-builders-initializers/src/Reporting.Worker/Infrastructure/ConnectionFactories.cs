using Npgsql;
using RabbitMQ.Client;
using Microsoft.Data.SqlClient;

namespace Reporting.Worker.Infrastructure
{
    internal static class ConnectionFactories
    {
        public static NpgsqlConnection Warehouse()
        {
            var csb = new NpgsqlConnectionStringBuilder
            {
                Host = "pg-warehouse.internal",
                Port = 5432,
                Database = "analytics",
                Username = "report_reader",
~>                Password = "Rpt-Reader-4471",
                SslMode = SslMode.Require,
            };
            return new NpgsqlConnection(csb.ConnectionString);
        }

        public static SqlConnection Ledger()
        {
            var builder = new SqlConnectionStringBuilder();
            builder.DataSource = "sql-ledger01";
            builder.InitialCatalog = "Ledger";
            builder.UserID = "ledger_rw";
~>            builder.Password = "L3dg3r-RW-pass";
            return new SqlConnection(builder.ConnectionString);
        }

        public static IConnection Queue()
        {
            var factory = new ConnectionFactory
            {
                HostName = "mq01.internal",
                UserName = "reporting",
~>                Password = "Mq-Rep0rting-88",
                VirtualHost = "/reports",
            };
            return factory.CreateConnection();
        }
    }
}
