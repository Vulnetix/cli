using System.IO;
using System.Net;
using System.Xml;

namespace Imports
{
    public class FeedImporter
    {
        public XmlDocument Load(Stream body)
        {
            var doc = new XmlDocument();
~>            doc.XmlResolver = new XmlUrlResolver();
            doc.Load(body);
            return doc;
        }

        public XmlReader Reader(Stream body)
        {
            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Parse,
~>                XmlResolver = new XmlUrlResolver(),
            };
            return XmlReader.Create(body, settings);
        }

        public XmlDocument WithCredentials(Stream body)
        {
            var resolver = new XmlUrlResolver();
            resolver.Credentials = CredentialCache.DefaultCredentials;
            var doc = new XmlDocument();
~>            doc.XmlResolver = resolver;
            doc.Load(body);
            return doc;
        }

        public string Text(TextReader input)
        {
            var reader = new XmlTextReader(input);
~>            reader.XmlResolver = new System.Xml.XmlUrlResolver();
            reader.DtdProcessing = DtdProcessing.Parse;
            reader.MoveToContent();
            return reader.ReadOuterXml();
        }
    }
}
