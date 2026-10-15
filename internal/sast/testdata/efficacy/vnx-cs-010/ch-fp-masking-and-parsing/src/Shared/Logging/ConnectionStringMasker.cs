using System;
using System.Text.RegularExpressions;

namespace Shared.Logging
{
    public static class ConnectionStringMasker
    {
        private static readonly Regex PasswordPart = new Regex("(Password|Pwd)=[^;]*", RegexOptions.IgnoreCase);

        public static string Mask(string connectionString)
        {
            return PasswordPart.Replace(connectionString, "$1=******");
        }

        public static string Password(string connectionString)
        {
            foreach (var part in connectionString.Split(';'))
            {
                if (part.StartsWith("Password=", StringComparison.OrdinalIgnoreCase))
                {
                    return part.Substring("Password=".Length);
                }
            }
            return null;
        }

        public static void Guard(string connectionString)
        {
            if (connectionString.Contains("Password=", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("Use Integrated Security=true instead of Password=... in the connection string");
            }
        }
    }
}
