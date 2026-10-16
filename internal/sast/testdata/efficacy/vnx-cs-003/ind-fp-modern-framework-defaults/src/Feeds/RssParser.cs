using System.IO;
using System.Xml;

namespace Feeds
{
    public class RssParser
    {
        public XmlDocument Parse(Stream body)
        {
            var doc = new XmlDocument();
            doc.Load(body);
            return doc;
        }

        public void ParseWithEntities(Stream body)
        {
            var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse };
            using var reader = XmlReader.Create(body, settings);
            while (reader.Read()) { }
        }
    }
}
