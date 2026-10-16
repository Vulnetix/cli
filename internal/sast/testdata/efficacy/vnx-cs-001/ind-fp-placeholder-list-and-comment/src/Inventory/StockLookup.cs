using System.Collections.Generic;
using System.Data.SqlClient;

namespace Inventory
{
    public class StockLookup
    {
        public Dictionary<string, int> Levels(SqlConnection conn, IReadOnlyList<string> skus)
        {
            var names = new List<string>();
            using var cmd = conn.CreateCommand();
            for (var i = 0; i < skus.Count; i++)
            {
                names.Add("@p" + i);
                cmd.Parameters.AddWithValue("@p" + i, skus[i]);
            }

            // Previously: cmd.CommandText = "SELECT Sku, Qty FROM Stock WHERE Sku IN ('" + string.Join("','", skus) + "')";
            cmd.CommandText = "SELECT Sku, Qty FROM Stock WHERE Sku IN (" + string.Join(", ", names) + ")";

            var result = new Dictionary<string, int>();
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                result[reader.GetString(0)] = reader.GetInt32(1);
            }
            return result;
        }

        public string Describe()
        {
            return "Do not write new SqlCommand(\"SELECT * FROM Stock WHERE Sku = '\" + sku + \"'\") here";
        }
    }
}
