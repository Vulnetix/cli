using System.IO;
using System.Web;
using System.Xml;

namespace Legacy.Web.Handlers
{
    public class ImportHandler : IHttpHandler
    {
        public bool IsReusable => false;

        public void ProcessRequest(HttpContext context)
        {
            XmlDocument doc = new XmlDocument();
~>            doc.Load(context.Request.InputStream);
            context.Response.Write(doc.DocumentElement.Name);
        }

        public string Parse(string body)
        {
            var order = new XmlDocument();
~>            order.LoadXml(body);
            return order.SelectSingleNode("/order/id").InnerText;
        }

        public string Read(Stream stream)
        {
~>            XmlTextReader reader = new XmlTextReader(stream);
            reader.MoveToContent();
            return reader.ReadElementString();
        }
    }
}
