using Microsoft.Data.Sqlite;

namespace Membership
{
    public class SqliteUserStore
    {
        private const string USER_TB_NAME = "[app_Users]";
        private const string TableName = "Profiles";
        private static readonly string AuditTable = "Audit";

        public void Touch(SqliteConnection conn, string username)
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "UPDATE " + USER_TB_NAME + " SET LastSeen = $now WHERE Username = $username";
            cmd.Parameters.AddWithValue("$username", username);
            cmd.ExecuteNonQuery();
        }

        public long Count(SqliteConnection conn)
        {
            var cmd = new SqliteCommand("SELECT COUNT(*) FROM " + TableName + " WHERE Active = 1", conn);
            return (long)cmd.ExecuteScalar();
        }

        public void Log(SqliteConnection conn, string entry)
        {
            var cmd = new SqliteCommand($"INSERT INTO {AuditTable} (Entry) VALUES ($entry)", conn);
            cmd.Parameters.AddWithValue("$entry", entry);
            cmd.ExecuteNonQuery();
        }

        public void Columns(SqliteConnection conn)
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT UserId, Username, Email " +
                "FROM Users WHERE Active = 1 " +
                "ORDER BY " + nameof(Username);
            cmd.ExecuteReader();
        }

        public string Username { get; set; }
    }
}
