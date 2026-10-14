namespace Billing
{
    internal static class DbSettings
    {
~>        public const string SqlServer = "Data Source=prod-sql;Initial Catalog=Billing;User ID=sa;Password=Winter2024!;";

~>        public static readonly string Express = @"Data Source=.\SQLEXPRESS;Initial Catalog=Hr;Uid=hr;Pwd=hr-pass-77;";

~>        internal static string Postgres = "Host=pg.internal;Port=5432;Username=report;Password=r3p0rt!;Database=analytics";

~>        private const string MySql = "server=mysql;uid=root;pwd=t0psecret;database=shop";

~>        private const string Oracle = "Data Source=ORCL;User Id=billing;Password = 'Bill#Pass9';";

~>        private const string Access = "Provider=Microsoft.ACE.OLEDB.12.0;Data Source=C:\\data\\legacy.accdb;Jet OLEDB:Database Password=Acc3ss!";
    }
}
