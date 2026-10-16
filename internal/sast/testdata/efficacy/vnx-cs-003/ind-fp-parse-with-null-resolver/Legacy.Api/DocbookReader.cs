using System.IO;
using System.Xml;

namespace Legacy.Api
{
    public class DocbookReader
    {
        public XmlDocument Read(Stream input)
        {
            var settings = new XmlReaderSettings();
            settings.DtdProcessing = DtdProcessing.Parse;
            settings.XmlResolver = null;
            settings.MaxCharactersFromEntities = 1024;
            var doc = new XmlDocument { XmlResolver = null };
            using (var reader = XmlReader.Create(input, settings))
            {
                doc.Load(reader);
            }
            return doc;
        }

        public XmlDocument Template()
        {
            var doc = new XmlDocument();
            doc.LoadXml("<template><section/></template>");
            return doc;
        }
    }
}
