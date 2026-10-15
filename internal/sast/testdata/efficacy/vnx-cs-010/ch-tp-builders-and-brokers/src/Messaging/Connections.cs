using Microsoft.Data.SqlClient;
using Npgsql;
using RabbitMQ.Client;
using StackExchange.Redis;

namespace Messaging
{
    public static class Connections
    {
        public static IConnection Broker()
        {
~>            var factory = new @@sample:C[o]nn[e]ct[i]on[F]ac[t]or[y]@@ { HostName = "mq01", UserName = "orders", Password = "0rd3rs-MQ" };
            return factory.CreateConnection();
        }

        public static string Sql()
        {
            var csb = new SqlConnectionStringBuilder
            {
                DataSource = "sql01",
                InitialCatalog = "Payroll",
                UserID = "payroll_svc",
~>                Password = "Payr0ll!Svc",
            };
            return csb.ConnectionString;
        }

        public static string Pg()
        {
            var b = new NpgsqlConnectionStringBuilder("Host=pg01;Database=crm");
            b.Username = "crm";
~>            b.Password = "crm-Pg-77";
            return b.ConnectionString;
        }

        public static ConfigurationOptions Redis()
        {
            var options = ConfigurationOptions.Parse("cache01:6379");
~>            options.Password = "c4ch3-R3d1s";
            return options;
        }
    }
}
