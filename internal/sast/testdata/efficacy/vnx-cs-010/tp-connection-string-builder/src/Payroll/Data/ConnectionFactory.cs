using Microsoft.Data.SqlClient;
using MySqlConnector;
using Npgsql;

namespace Payroll.Data
{
    public static class ConnectionFactory
    {
        public static SqlConnection Payroll()
        {
            var builder = new SqlConnectionStringBuilder
            {
                DataSource = "sql01",
                InitialCatalog = "Payroll",
                UserID = "payroll",
~>                Password = "Pay-r0ll-2023",
                Encrypt = true,
            };
            return new SqlConnection(builder.ConnectionString);
        }

        public static NpgsqlConnection Warehouse(string baseConnection)
        {
            var csb = new NpgsqlConnectionStringBuilder(baseConnection);
            csb.Username = "warehouse";
~>            csb.Password = "Npg-Secret-1";
            return new NpgsqlConnection(csb.ConnectionString);
        }

        public static MySqlConnection Shop()
        {
            MySqlConnectionStringBuilder b = new();
            b.Server = "mysql01";
~>            b["Password"] = "My-Sql-Pa55";
            return new MySqlConnection(b.ConnectionString);
        }
    }
}
