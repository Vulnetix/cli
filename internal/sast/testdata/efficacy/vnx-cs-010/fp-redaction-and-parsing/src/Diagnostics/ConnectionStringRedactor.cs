using System;
using System.Data.Common;
using System.Text.RegularExpressions;

namespace Diagnostics
{
    public static class ConnectionStringRedactor
    {
        private static readonly Regex Secret = new Regex("Password=[^;]*", RegexOptions.IgnoreCase);

        public static string Redact(string connectionString)
        {
            var safe = Secret.Replace(connectionString, "Password=***");
            return Regex.Replace(safe, "(?i)(pwd|password)=[^;]*", "$1=***");
        }

        public static bool HasPassword(string connectionString)
        {
            var b = new DbConnectionStringBuilder { ConnectionString = connectionString };
            return b.ContainsKey("Password") || connectionString.Contains("Pwd=", StringComparison.OrdinalIgnoreCase);
        }

        public static string Describe(DbConnectionStringBuilder b)
        {
            b.Remove("Password");
            return b.ConnectionString;
        }
    }
}
