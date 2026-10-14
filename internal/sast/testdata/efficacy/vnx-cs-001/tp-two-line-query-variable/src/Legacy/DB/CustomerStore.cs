using System.Data;
using MySql.Data.MySqlClient;
using Npgsql;

namespace Legacy.DB
{
    public class CustomerStore
    {
        private readonly string _connectionString;

        public CustomerStore(string connectionString) => _connectionString = connectionString;

        public DataSet FindCustomer(string email, string status)
        {
            string sql = "select * from Customers where email = '" + email +
                "' and status = '" + status + "';";

            using (MySqlConnection connection = new MySqlConnection(_connectionString))
            {
~>                MySqlDataAdapter da = new MySqlDataAdapter(sql, connection);
                DataSet ds = new DataSet();
                da.Fill(ds);
                return ds;
            }
        }

        public int CountByRegion(NpgsqlConnection conn, string region, string tier)
        {
            var query = "SELECT COUNT(*) FROM customers WHERE 1 = 1";
            if (!string.IsNullOrEmpty(tier))
            {
                query += " AND tier = '" + tier + "'";
            }
~>            using var cmd = new NpgsqlCommand(query, conn);
            return (int)cmd.ExecuteScalar();
        }

        public string GetEmail(string customerNumber)
        {
            using (MySqlConnection connection = new MySqlConnection(_connectionString))
            {
                string text = string.Format("select email from Customers where number = {0}", customerNumber);
                var command = connection.CreateCommand();
~>                command.CommandText = text;
                return command.ExecuteScalar().ToString();
            }
        }
    }
}
