using System.Linq;
using System.Threading.Tasks;
using Dapper;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;

namespace Catalog
{
    public class ProductQueries
    {
        private readonly CatalogContext _db;
        private readonly SqlConnection _conn;

        public ProductQueries(CatalogContext db, SqlConnection conn)
        {
            _db = db;
            _conn = conn;
        }

        public Product[] ByCategory(string category)
        {
            return _db.Products
                .FromSqlInterpolated($"SELECT * FROM Products WHERE Category = {category}")
                .ToArray();
        }

        public Task<Product> BySku(string sku)
        {
            return _conn.QueryFirstOrDefaultAsync<Product>(
                "SELECT * FROM Products WHERE Sku = @Sku",
                new { Sku = sku });
        }

        public int Discontinue(int productId)
        {
            FormattableString sql = $"UPDATE Products SET Discontinued = 1 WHERE Id = {productId}";
            return _db.Database.ExecuteSqlInterpolated(sql);
        }

        public Product[] Cheap(decimal max)
        {
            return _db.Products.Where(p => p.Price <= max).OrderBy(p => p.Price).ToArray();
        }
    }
}
