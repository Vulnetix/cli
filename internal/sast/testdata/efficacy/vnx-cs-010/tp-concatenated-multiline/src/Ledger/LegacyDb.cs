using System.Data.SqlClient;

namespace Ledger
{
    internal static class LegacyDb
    {
        private static readonly string Conn = "Server=10.0.4.12;Database=Ledger;" +
~>            "User Id=ledger;Password=L3dger#2023;";

        private static readonly string Archive =
            "Server=archive01;Initial Catalog=LedgerArchive;" +
            "Persist Security Info=False;" +
~>            "Password=Arch1ve!;User ID=archiver;";

        private static readonly string Hr = "Data Source=hr-sql;Initial Catalog=Hr;User ID=hr_app;" +
~>            "Password=Hr-Only-1;";

        public static SqlConnection Open() => new SqlConnection(Conn);
    }
}
