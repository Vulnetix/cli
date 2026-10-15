using System.IO;
using System.Xml;

namespace Docs
{
    public class DocBookReader
    {
        public XmlDocument Read(Stream input)
        {
            var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse };
            using var reader = XmlReader.Create(input, settings);
            var doc = new XmlDocument();
            doc.Load(reader);
            return doc;
        }

        public bool IsParse(XmlReaderSettings s)
        {
            return s.DtdProcessing == DtdProcessing.Parse;
        }
    }
}
