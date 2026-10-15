using Dapper;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;

namespace Shop.Data;

public class OrderStore
{
    private readonly ShopDbContext _db;
    private readonly SqlConnection _conn;

    public OrderStore(ShopDbContext db, SqlConnection conn)
    {
        _db = db;
        _conn = conn;
    }

    public Task<List<Order>> ByCustomer(string customer) =>
        _db.Orders.FromSqlInterpolated($"SELECT * FROM Orders WHERE Customer = {customer}").ToListAsync();

    public Task<int> Cancel(int id) =>
        _db.Database.ExecuteSqlInterpolatedAsync($"UPDATE Orders SET Cancelled = 1 WHERE Id = {id}");

    public Task<Order?> One(int id) =>
        _conn.QuerySingleOrDefaultAsync<Order>("SELECT * FROM Orders WHERE Id = @id", new { id });

    public async Task<int> Touch(string region)
    {
        using var cmd = new SqlCommand("UPDATE Orders SET Touched = SYSUTCDATETIME() WHERE Region = @region", _conn);
        cmd.Parameters.AddWithValue("@region", region);
        return await cmd.ExecuteNonQueryAsync();
    }

    public Task<List<Order>> Raw(string status) =>
        _db.Orders.FromSqlRaw("SELECT * FROM Orders WHERE Status = {0}", status).ToListAsync();
}
