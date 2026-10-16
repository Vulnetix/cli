using System.IO;
using System.Web;
using System.Xml;

namespace OrderService
{
    public class OrderHandler : IHttpHandler
    {
        public bool IsReusable => false;

        public void ProcessRequest(HttpContext context)
        {
            XmlDocument doc = new XmlDocument();
~>            doc.Load(context.Request.InputStream);
            var id = doc.SelectSingleNode("/order/@id")?.Value;
            context.Response.Write(id);
        }

        public string Customer(string body)
        {
            var doc = new XmlDocument();
~>            doc.LoadXml(body);
            return doc.SelectSingleNode("//customer")?.InnerText;
        }

        public void Stream(Stream input)
        {
~>            using (var reader = new XmlTextReader(input))
            {
                while (reader.Read()) { }
            }
        }
    }
}
