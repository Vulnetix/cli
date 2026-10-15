using System.Collections.Generic;
using System.Net.Http;

namespace Acme.Web
{
    public class Globals
    {
~>        public static HttpClient Client = new HttpClient();
~>        public static string ConnectionString;
~>        static public List<string> AllowedHosts = new();
~>        public static Func<int, int> Twice = x => x * 2;
~>        public static Dictionary<string, int> Limits = new Dictionary<string, int>();
    }
}
