using System.IO;
using System.Xml;

namespace Shop.Import;

public class CatalogImporter
{
    public XmlReader Open(Stream upload)
    {
        XmlReaderSettings settings = new XmlReaderSettings();
        settings.DtdProcessing = DtdProcessing.Parse;
~>        settings.XmlResolver = new XmlUrlResolver();
        return XmlReader.Create(upload, settings);
    }
}
