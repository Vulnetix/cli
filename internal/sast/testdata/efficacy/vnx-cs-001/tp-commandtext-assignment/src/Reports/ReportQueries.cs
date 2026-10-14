using System.Data.SqlClient;
using Microsoft.Data.Sqlite;

namespace Reports
{
    public static class ReportQueries
    {
        public static void UpdateEmail(SqlConnection conn, string email, int userId)
        {
            using var cmd = conn.CreateCommand();
~>            cmd.CommandText = "UPDATE Users SET Email = '" + email + "' WHERE Id = " + userId;
            cmd.ExecuteNonQuery();
        }

        public static SqlDataReader Search(SqlConnection conn, string term)
        {
            var command = conn.CreateCommand();
~>            command.CommandText = string.Format("SELECT * FROM Products WHERE Name LIKE '%{0}%'", term);
            return command.ExecuteReader();
        }

        public static SqliteDataReader Notes(SqliteConnection conn, string owner)
        {
            var cmd = new SqliteCommand
            {
                Connection = conn,
~>                CommandText = $"SELECT * FROM Notes WHERE Owner = '{owner}'",
            };
            return cmd.ExecuteReader();
        }
    }
}
