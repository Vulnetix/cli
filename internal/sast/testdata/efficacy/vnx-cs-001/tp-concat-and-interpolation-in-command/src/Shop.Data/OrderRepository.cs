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

        public int CountOrders(string customerId)
        {
            using (var conn = new SqlConnection(_connectionString))
            {
                conn.Open();
~>                var cmd = new SqlCommand("SELECT COUNT(*) FROM Orders WHERE CustomerId = '" + customerId + "'", conn);
                return (int)cmd.ExecuteScalar();
            }
        }

        public void DeleteOrder(string orderId)
        {
            using var conn = new SqlConnection(_connectionString);
            conn.Open();
~>            using var cmd = new SqlCommand($"DELETE FROM Orders WHERE Id = {orderId}", conn);
            cmd.ExecuteNonQuery();
        }

        public void Archive(string region)
        {
            using var conn = new SqlConnection(_connectionString);
~>            SqlCommand cmd = new("UPDATE Orders SET Archived = 1 WHERE Region = '" + region + "'", conn);
            cmd.ExecuteNonQuery();
        }

        public object Lookup(System.Data.OleDb.OleDbConnection oleConn, string code)
        {
~>            var oleCmd = new System.Data.OleDb.OleDbCommand(string.Format("SELECT Name FROM Products WHERE Code = '{0}'", code), oleConn);
            return oleCmd.ExecuteScalar();
        }
    }
}
