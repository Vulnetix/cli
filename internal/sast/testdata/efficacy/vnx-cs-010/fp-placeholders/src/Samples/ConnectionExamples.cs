namespace Samples
{
    public static class ConnectionExamples
    {
        public const string SqlServerTemplate = "Server=myServerAddress;Database=myDataBase;User Id=myUsername;Password=myPassword;";

        public const string Angle = "Server=db;Database=app;User Id=app;Password=<password>;";

        public const string Upper = "Host=db;Username=app;Password=YOUR_PASSWORD;Database=app";

        public const string Stars = "Data Source=db;User ID=app;Password=********;";

        public const string Octopus = "Server=#{DbServer};User Id=#{DbUser};Password=#{DbPassword};";

        public const string Msbuild = "Server=$(SqlServer);User Id=sa;Password=$(SqlPassword);";

        public const string Env = "Server=%DB_HOST%;User Id=sa;Password=%DB_PASS%;";

        public const string Token = "Server=db;User Id=app;Password=__DB_PASSWORD__;";

        public const string Brackets = "Server=db;User Id=app;Password=[password];";
    }
}
