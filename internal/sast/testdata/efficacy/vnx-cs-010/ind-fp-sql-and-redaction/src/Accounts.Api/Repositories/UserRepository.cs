using System.Data;
using System.Text.RegularExpressions;
using Dapper;
using Microsoft.Data.SqlClient;

namespace Accounts.Api.Repositories
{
    public sealed class UserRepository
    {
        private static readonly Regex PasswordPart = new Regex("(Password|Pwd)=[^;]*", RegexOptions.IgnoreCase);

        private readonly IDbConnection _db;

        public UserRepository(IDbConnection db) => _db = db;

        public int UpdatePasswordHash(int id, string hash) =>
            _db.Execute("UPDATE Users SET Password = @p WHERE Id = @id", new { p = hash, id });

        public bool Exists(string user, string hash) =>
            _db.ExecuteScalar<int>("SELECT COUNT(1) FROM Users WHERE UserName = @user AND Password = @hash", new { user, hash }) > 0;

        public static string Redact(string connectionString) =>
            PasswordPart.Replace(connectionString, "$1=***");

        public static bool HasPassword(string connectionString) =>
            !string.IsNullOrEmpty(new SqlConnectionStringBuilder(connectionString).Password);
    }
}
