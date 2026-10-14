using System;
using System.Data.Common;

namespace Setup
{
    public static class Validation
    {
        public const string PasswordKey = "Password";

        public static void RejectInline(string connectionString)
        {
            var b = new DbConnectionStringBuilder { ConnectionString = connectionString };
            if (b.ContainsKey(PasswordKey))
            {
                throw new ArgumentException("Password=... is not allowed in the connection string; use Integrated Security");
            }
        }

        public static Uri LoginLink(string user) => new Uri("https://intranet.example/login?user=" + user + "&pwd=");

        public static string Help() => "Set the DB_PASSWORD environment variable; the connection string must not contain Password=.";

        public static string Mask(string connectionString) =>
            connectionString.Replace("Password=", "Password=<hidden>;", StringComparison.OrdinalIgnoreCase);
    }
}
