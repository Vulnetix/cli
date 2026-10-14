using System.Data.OleDb;
using System.Data.SqlClient;
using System.Text;

namespace Audit
{
    public class AuditLog
    {
        public SqlDataReader Filter(SqlConnection conn, string level, string source)
        {
            var sb = new StringBuilder("SELECT * FROM Logs WHERE 1 = 1");
            sb.Append(" AND Level = '" + level + "'");
            sb.AppendFormat(" AND Source = '{0}'", source);
            var cmd = conn.CreateCommand();
~>            cmd.CommandText = sb.ToString();
            return cmd.ExecuteReader();
        }

        public object Owner(OleDbConnection conn, string owner)
        {
~>            var cmd = new OleDbCommand(
                "SELECT Balance FROM Accounts WHERE Owner = '" + owner + "'",
                conn);
            return cmd.ExecuteScalar();
        }
    }
}
