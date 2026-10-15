using System.IO;
using System.Xml;
using System.Xml.Linq;
using System.Xml.XPath;

namespace Shop.Import;

public static class Readers
{
    public static XmlReader Open(Stream s) => XmlReader.Create(s);

    public static XPathDocument Path(Stream s) => new XPathDocument(XmlReader.Create(s, new XmlReaderSettings()));

    public static XElement Element(string xml) => XElement.Parse(xml);

    public static bool IsUrlResolver(XmlResolver r) => r is XmlUrlResolver;
}
