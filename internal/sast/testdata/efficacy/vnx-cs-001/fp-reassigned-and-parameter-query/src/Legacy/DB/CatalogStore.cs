using System.Data;
using System.Data.SQLite;

namespace Legacy.DB
{
    public class CatalogStore
    {
        private readonly string _connectionString;

        public CatalogStore(string connectionString) => _connectionString = connectionString;

        public DataSet Products(string category)
        {
            string sql = "select * from Products where category = @category";
            using (SQLiteConnection connection = new SQLiteConnection(_connectionString))
            {
                SQLiteDataAdapter da = new SQLiteDataAdapter(sql, connection);
                da.SelectCommand.Parameters.AddWithValue("@category", category);
                DataSet ds = new DataSet();
                da.Fill(ds);
                return ds;
            }
        }

        public DataSet AllCategories()
        {
            using (SQLiteConnection connection = new SQLiteConnection(_connectionString))
            {
                string sql = "select * from Categories;";
                SQLiteDataAdapter da = new SQLiteDataAdapter(sql, connection);
                DataSet ds = new DataSet();
                da.Fill(ds);
                return ds;
            }
        }

        public DataSet Search(string term)
        {
            string sql = "select * from Products";
            sql = "select * from Products where name like @term";
            using (SQLiteConnection connection = new SQLiteConnection(_connectionString))
            {
                SQLiteDataAdapter da = new SQLiteDataAdapter(sql, connection);
                da.SelectCommand.Parameters.AddWithValue("@term", "%" + term + "%");
                DataSet ds = new DataSet();
                da.Fill(ds);
                return ds;
            }
        }

        private int RunNonQuery(string sql, SQLiteConnection conn)
        {
            var cmd = new SQLiteCommand(sql, conn);
            return cmd.ExecuteNonQuery();
        }
    }
}
