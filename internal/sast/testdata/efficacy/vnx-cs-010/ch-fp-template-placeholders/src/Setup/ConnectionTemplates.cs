namespace Setup
{
    public static class ConnectionTemplates
    {
        public const string SqlServer = "Server=localhost;Database=App;User Id=app;Password=REPLACE_ME;";
        public const string Postgres = "Host=localhost;Database=app;Username=app;Password=$DB_PASSWORD";
        public const string Mustache = "Server={{DbServer}};User Id={{DbUser}};Password={{DbPassword}};";
        public const string Todo = "Server=localhost;User Id=app;Password=TODO;";
        public const string Angle = "@@sample:S[e]rv[e]r[=][l]oc[a]lh[o]st@@;User Id=app;Password=<<db-password>>;";
    }
}
