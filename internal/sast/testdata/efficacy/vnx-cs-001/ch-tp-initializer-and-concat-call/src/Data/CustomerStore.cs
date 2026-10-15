using System.Data.SqlClient;

namespace Shop.Data
{
    public class CustomerStore
    {
        private readonly SqlConnection _conn;

        public CustomerStore(SqlConnection conn) { _conn = conn; }

        public int Remove(string customerId)
        {
            var cmd = new SqlCommand
            {
                Connection = _conn,
~>                CommandText = "DELETE FROM Customers WHERE CustomerId = '" + customerId + "'"
            };
            return cmd.ExecuteNonQuery();
        }

        public SqlDataReader Find(string email)
        {
            string query = string.Concat("SELECT * FROM Customers WHERE Email = '", email, "'");
~>            using var command = new SqlCommand(query, _conn);
            return command.ExecuteReader();
        }
    }
}
