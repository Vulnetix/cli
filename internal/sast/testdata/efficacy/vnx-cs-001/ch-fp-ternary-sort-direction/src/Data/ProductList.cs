using Microsoft.Data.SqlClient;

namespace Shop.Data;

public class ProductList
{
    public SqlCommand Page(SqlConnection conn, bool descending, int take)
    {
        var sql = "SELECT TOP (@take) Id, Name FROM Products ORDER BY Name " + (descending ? "DESC" : "ASC");
        var cmd = new SqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@take", take);
        return cmd;
    }

    public SqlCommand Filter(SqlConnection conn, bool activeOnly)
    {
        var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT Id FROM Products" + (activeOnly ? " WHERE Active = 1" : string.Empty);
        return cmd;
    }
}
