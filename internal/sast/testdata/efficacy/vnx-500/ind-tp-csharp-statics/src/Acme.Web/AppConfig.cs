using System.Collections.Generic;

namespace Acme.Web
{
    public static class AppConfig
    {
~>        public static string ConnectionString = "Server=db;Database=app";
~>        public static int RequestTimeoutSeconds;
~>        static public List<string> AllowedOrigins = new List<string> { "https://app.example.com" };
        [System.Obsolete("use options")]
~>        public static bool EnableLegacyAuth = false;
    }
}
