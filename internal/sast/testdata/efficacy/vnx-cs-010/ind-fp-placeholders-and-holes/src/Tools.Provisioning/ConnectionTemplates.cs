namespace Tools.Provisioning
{
    public static class ConnectionTemplates
    {
        public const string SqlTemplate = "Server=<server>;Database=<database>;User Id=<user>;Password=<password>;";
        public const string OctopusTemplate = "Server=#{DbServer}#;Database=Orders;User Id=#{DbUser}#;Password=#{DbPassword}#;";
        public const string PipelineTemplate = "Host=$(PgHost);Username=app;Password=$(SqlPassword);Database=app";
        public const string Sample = "Server=myServer;Database=myDataBase;User Id=myUsername;Password=myPassword;";
        public const string Tokenised = "Server=db;Database=app;User Id=app;Password=__DB_PASSWORD__;";
        public const string EmptyPwd = "Server=localhost;Database=scratch;User Id=sa;Password=;";

        public static string Build(string server, string user, string password) =>
            string.Format("Server={0};Database=Orders;User Id={1};Password={2};", server, user, password);

        public static string Pg(string host, string pwd) =>
            $"Host={host};Port=5432;Username=etl;Password={pwd};Database=etl";

        public static string Concat(string host, string pwd) =>
            "Server=" + host + ";Database=Billing;User Id=billing;Password=" + pwd + ";";
    }
}
