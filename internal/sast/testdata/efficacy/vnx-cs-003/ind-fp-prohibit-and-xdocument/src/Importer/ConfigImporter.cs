using System.IO;
using System.Xml;
using System.Xml.Linq;

namespace Importer
{
    public class ConfigImporter
    {
        public XDocument LoadLinq(Stream input)
        {
            return XDocument.Load(input);
        }

        public int CountNodes(Stream input)
        {
            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
            };
            var n = 0;
            using var reader = XmlReader.Create(input, settings);
            while (reader.Read()) n++;
            return n;
        }

        public void Skim(TextReader text)
        {
            var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Ignore };
            using var reader = XmlReader.Create(text, settings);
            while (reader.Read()) { }
        }
    }
}
