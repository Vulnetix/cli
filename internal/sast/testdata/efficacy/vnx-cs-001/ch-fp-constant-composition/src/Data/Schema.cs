using Microsoft.Data.SqlClient;

namespace Shop.Data;

public static class Schema
{
    private const string Table = "dbo.Products";
    private const string Columns = "Id, Name, Price";

    public static int Count(SqlConnection conn)
    {
        var sql = "SELECT COUNT(*) FROM " + Table;
        using var cmd = new SqlCommand(sql, conn);
        return (int)cmd.ExecuteScalar();
    }

    public static SqlCommand Select(SqlConnection conn, int id)
    {
        var cmd = new SqlCommand($"SELECT {Columns} FROM {Table} WHERE Id = @id", conn);
        cmd.Parameters.AddWithValue("@id", id);
        return cmd;
    }

    public static SqlCommand Page(SqlConnection conn, int take)
    {
        var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT TOP (@take) " + Columns + " FROM " + Table + " ORDER BY " + nameof(Product.Id);
        cmd.Parameters.AddWithValue("@take", take);
        return cmd;
    }
}
