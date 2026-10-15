using System.Net;

namespace Billing
{
    public class Exporter
    {
~>        private const string Target = "ftps://exporter:Pm8vRq3XtL5n@@@sample:f[i]le[s][.]a[c]me[-]co[r]p[.][i]o[/][b]il[l]in[g][/]@@";

        public void Push(string file)
        {
            using var client = new WebClient();
            client.UploadFile(Target + file, file);
        }
    }
}
