using System.IO;
using System.Xml;

namespace Docs
{
    public class DocBookReader
    {
        public XmlReader Open(Stream input)
        {
            // DocBook needs its DTD for character entities; no resolver is set,
            // so on .NET Framework 4.5.2+ and .NET no external entity is fetched.
            var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse, MaxCharactersFromEntities = 1024 };
            return XmlReader.Create(input, settings);
        }

        public XmlDocument Load(Stream input)
        {
            var doc = new XmlDocument();
            doc.Load(input);
            return doc;
        }

        public XmlTextReader Text(Stream input)
        {
            var reader = new XmlTextReader(input);
            return reader;
        }
    }
}
