using System.Xml;
using System.Xml.Linq;

namespace Parsing;

public static class ConfigParser
{
    public static XmlDocument Parse(string xml)
    {
        var doc = new XmlDocument();
        doc.LoadXml(xml);
        return doc;
    }

    public static XDocument ParseLinq(string xml) => XDocument.Parse(xml);

    public static XmlTextReader Reader(System.IO.Stream s) => new XmlTextReader(s);

    // XmlResolver = new XmlUrlResolver() is what we must never do here.
    public const string Hint = "settings.DtdProcessing = DtdProcessing.Parse enables entity expansion";
}
