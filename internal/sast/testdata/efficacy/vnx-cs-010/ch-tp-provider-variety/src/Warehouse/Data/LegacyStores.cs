using System.Data.OleDb;
using FirebirdSql.Data.FirebirdClient;
using MySqlConnector;
using Oracle.ManagedDataAccess.Client;

namespace Warehouse.Data
{
    internal static class LegacyStores
    {
~>        private const string InventoryDb = "@@sample:s[e]rv[e]r[=][m]ys[q]l[-][i]nv@@;port=3306;@@sample:d[a]ta[b]as[e][=]i[n]ve[n]to[r]y@@;uid=inv_rw;pwd=Inv#2291x";

        public static MySqlConnection Inventory() => new MySqlConnection(InventoryDb);

        public static OracleConnection Ledger()
        {
~>            return new @@sample:O[r]ac[l]eC[o]nn[e]ct[i]on@@("Data @@sample:S[o]ur[c]e[=][L]ED[G]ER[P]DB@@;User Id=ledger;@@sample:P[a]ss[w]or[d][=]L[d]g3[r][_]P[r]0d@@;");
        }

        public static FbConnection Archive()
        {
~>            var cs = "User=SYSDBA;@@sample:P[a]ss[w]or[d][=]m[a]st[e]rk[e]y@@;@@sample:D[a]ta[b]as[e][=][/][v]ar[/]li[b][/]f[i]re[b]ir[d][/]a[r]ch[i]ve[.]fd[b]@@;DataSource=fb01;";
            return new FbConnection(cs);
        }

        public static OleDbConnection Access()
        {
~>            return new OleDbConnection(@"@@sample:P[r]ov[i]de[r][=]M[i]cr[o]so[f]t[.][J]et[.]OL[E]DB[.]4[.][0]@@;Data Source=C:\data\pricing.mdb;Jet OLEDB:Database @@sample:P[a]ss[w]or[d][=]p[r]1c[1]ng@@;");
        }
    }
}
