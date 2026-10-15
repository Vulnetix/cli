using System.Web;
using System.Xml;

public class ImportHandler : IHttpHandler
{
    public bool IsReusable => false;

    public void ProcessRequest(HttpContext context)
    {
        var doc = new XmlDocument();
~>        doc.Load(context.Request.InputStream);
        context.Response.Write(doc.DocumentElement.Name);
    }
}
