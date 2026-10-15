using System.Collections.Generic;
using System.Data.Odbc;
using Microsoft.Extensions.Configuration;

namespace Reporting
{
    public static class Sources
    {
        public static OdbcConnection Warehouse()
        {
~>            return new OdbcConnection("Driver={ODBC Driver 18 for SQL Server};Server=dw01;Uid=report;Pwd=Odbc!Rpt9;");
        }

        public static string Regional(string host)
        {
~>            return string.Format("Server={0};@@sample:D[a]ta[b]as[e][=]R[e]gi[o]na[l]@@;User Id=sa;@@sample:P[a]ss[w]or[d][=]S[a]Pa[s]sw[0]rd@@!;", host);
        }

        public static IConfiguration InMemory()
        {
            return new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string>
                {
~>                    ["@@sample:C[o]nn[e]ct[i]on[S]tr[i]ng[s]@@:Default"] = "Server=db01;Database=Crm;User Id=crm;@@sample:P[a]ss[w]or[d][=]C[r]m[_][2]02[4][_]x@@;",
                })
                .Build();
        }
    }
}
