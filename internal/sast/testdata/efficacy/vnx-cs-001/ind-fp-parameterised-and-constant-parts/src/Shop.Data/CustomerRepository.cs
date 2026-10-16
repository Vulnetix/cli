using System.Data;
using System.Data.SqlClient;

namespace Shop.Data
{
    public class CustomerRepository
    {
        private const string TableName = "dbo.Customers";
        private static readonly string Columns = "Id, Email, DisplayName";
        private readonly string _connectionString;

        public CustomerRepository(string connectionString) => _connectionString = connectionString;

        public string GetDisplayName(string email)
        {
            string sql = "SELECT DisplayName FROM " + TableName + " WHERE Email = @email";
            using (var conn = new SqlConnection(_connectionString))
            using (var cmd = new SqlCommand(sql, conn))
            {
                cmd.Parameters.Add(new SqlParameter("@email", SqlDbType.NVarChar, 256) { Value = email });
                conn.Open();
                return (string)cmd.ExecuteScalar();
            }
        }

        public DataTable ListAll()
        {
            var table = new DataTable();
            using (var conn = new SqlConnection(_connectionString))
            using (var adapter = new SqlDataAdapter("SELECT " + Columns + " FROM " + TableName, conn))
            {
                adapter.Fill(table);
            }
            return table;
        }

        public void Touch(SqlCommand cmd, string email)
        {
            cmd.CommandText = "UPDATE " + TableName + " SET LastSeen = SYSUTCDATETIME() WHERE " + nameof(email) + " = @email";
            cmd.Parameters.AddWithValue("@email", email);
            cmd.ExecuteNonQuery();
        }
    }
}
