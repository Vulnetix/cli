using System.Collections.Generic;
using Microsoft.Data.SqlClient;

namespace Orders.Data
{
    public sealed class OrderRepository
    {
        public IReadOnlyList<int> OpenOrderIds()
        {
            var ids = new List<int>();
~>            using var conn = new SqlConnection("Server=db01.internal;Database=Orders;User Id=orders_app;Password=Q7v!m2Lp;");
            conn.Open();
            using var cmd = new SqlCommand("SELECT Id FROM Orders WHERE Status = @s", conn);
            cmd.Parameters.AddWithValue("@s", "open");
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                ids.Add(reader.GetInt32(0));
            }
            return ids;
        }

        public SqlConnection Reporting()
        {
            return new SqlConnection(
~>                "Data Source=report-sql;Initial Catalog=Reporting;User ID=reporter;Password=Rep0rt-Only!");
        }
    }
}
