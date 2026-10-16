using System.Collections.Generic;
using System.Data.SqlClient;

namespace Shop.Data
{
    public class OrderRepository
    {
        private readonly string _connectionString;

        public OrderRepository(string connectionString)
        {
            _connectionString = connectionString;
        }

        public List<int> FindOrderIds(string customerEmail, string status)
        {
            var ids = new List<int>();
            string sql = "SELECT o.Id FROM Orders o JOIN Customers c ON c.Id = o.CustomerId " +
                         "WHERE c.Email = '" + customerEmail + "' AND o.Status = '" + status + "'";

            using (var conn = new SqlConnection(_connectionString))
~>            using (var cmd = new SqlCommand(sql, conn))
            {
                conn.Open();
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        ids.Add(reader.GetInt32(0));
                    }
                }
            }
            return ids;
        }
    }
}
