using System.IO;
using System.Net;
using System.Xml;

namespace Shop.Import;

public class Importer
{
    public void Read(Stream s)
    {
        XmlResolver resolver = new XmlUrlResolver { Credentials = CredentialCache.DefaultCredentials };
        var reader = new XmlTextReader(s);
~>        reader.XmlResolver = resolver;
        while (reader.Read()) { }
    }
}
