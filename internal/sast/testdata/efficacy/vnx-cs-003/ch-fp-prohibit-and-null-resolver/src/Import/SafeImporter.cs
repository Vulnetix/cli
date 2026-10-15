using System.IO;
using System.Xml;

namespace Shop.Import;

public class SafeImporter
{
    public XmlReader Open(Stream upload)
    {
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
        };
        return XmlReader.Create(upload, settings);
    }

    public XmlReader Lenient(Stream upload)
    {
        var settings = new XmlReaderSettings();
        settings.DtdProcessing = DtdProcessing.Ignore;
        return XmlReader.Create(upload, settings);
    }

    public XmlDocument Load(string body)
    {
        var doc = new XmlDocument { XmlResolver = null };
        doc.LoadXml(body);
        return doc;
    }
}
