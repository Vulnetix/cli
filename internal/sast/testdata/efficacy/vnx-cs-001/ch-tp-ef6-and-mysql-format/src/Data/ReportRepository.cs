using System.Data.Entity;
using MySql.Data.MySqlClient;

namespace Shop.Data
{
    public class ReportRepository
    {
        private readonly ShopContext _db;
        private readonly string _cs;

        public ReportRepository(ShopContext db, string cs)
        {
            _db = db;
            _cs = cs;
        }

        public IList<Order> OrdersFor(string customer)
        {
~>            return _db.Database.SqlQuery<Order>("SELECT * FROM Orders WHERE Customer = '" + customer + "'").ToList();
        }

        public int Purge(string region)
        {
~>            return _db.Database.ExecuteSqlCommand(string.Format("DELETE FROM Orders WHERE Region = '{0}'", region));
        }

        public object Count(string status)
        {
            var sql = string.Format("SELECT COUNT(*) FROM Orders WHERE Status = '{0}'", status);
            using (var conn = new MySqlConnection(_cs))
~>            using (var cmd = new MySqlCommand(sql, conn))
            {
                conn.Open();
                return cmd.ExecuteScalar();
            }
        }
    }
}
