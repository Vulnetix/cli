using System.Data;
using System.Text;
using MySql.Data.MySqlClient;

namespace Reports
{
    public class AuditReport
    {
        public DataTable Load(MySqlConnection connection, string userName, string fromDate)
        {
            var sb = new StringBuilder();
            sb.Append("SELECT ts, action, target FROM audit_log WHERE 1=1");
            if (!string.IsNullOrEmpty(userName))
            {
                sb.Append(" AND user_name = '").Append(userName).Append("'");
            }
            sb.Append(" AND ts >= '" + fromDate + "'");

            using var cmd = connection.CreateCommand();
~>            cmd.CommandText = sb.ToString();
            var table = new DataTable();
            using var adapter = new MySqlDataAdapter(cmd);
            adapter.Fill(table);
            return table;
        }

        public DataTable ByAction(MySqlConnection connection, string action)
        {
            var table = new DataTable();
~>            using var adapter = new MySqlDataAdapter($"SELECT * FROM audit_log WHERE action = '{action}'", connection);
            adapter.Fill(table);
            return table;
        }
    }
}
