using System.Data;
using System.Data.SqlClient;
using Dapper;

namespace Shop.Data
{
    public class SafeOrderRepository
    {
        private readonly string _connectionString;

        public SafeOrderRepository(string connectionString) => _connectionString = connectionString;

        public int CountOrders(string customerId)
        {
            using var conn = new SqlConnection(_connectionString);
            conn.Open();
            using var cmd = new SqlCommand("SELECT COUNT(*) FROM Orders WHERE CustomerId = @customerId", conn);
            cmd.Parameters.Add(new SqlParameter("@customerId", SqlDbType.NVarChar, 64) { Value = customerId });
            return (int)cmd.ExecuteScalar();
        }

        public void Rename(SqlConnection conn, int id, string name)
        {
            string sql = "UPDATE Orders SET Name = @name WHERE Id = @id";
            using var cmd = new SqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("@name", name);
            cmd.Parameters.AddWithValue("@id", id);
            cmd.ExecuteNonQuery();
        }

        public Order Find(IDbConnection db, string login)
        {
            return db.QueryFirstOrDefault<Order>("SELECT * FROM Orders WHERE Login = @Login", new { Login = login });
        }

        public void ByIds(SqlConnection conn, int[] ids)
        {
            var names = new string[ids.Length];
            using var cmd = conn.CreateCommand();
            for (int i = 0; i < ids.Length; i++)
            {
                names[i] = "@p" + i;
                cmd.Parameters.AddWithValue("@p" + i, ids[i]);
            }
            cmd.CommandText = "SELECT * FROM Orders WHERE Id IN (" + string.Join(", ", names) + ")";
            cmd.ExecuteReader();
        }

        public void Proc(SqlConnection conn, int userId)
        {
            using var cmd = new SqlCommand("sp_GetUserById", conn) { CommandType = CommandType.StoredProcedure };
            cmd.Parameters.Add(new SqlParameter("@userId", SqlDbType.Int) { Value = userId });
            cmd.ExecuteReader();
        }
    }
}
