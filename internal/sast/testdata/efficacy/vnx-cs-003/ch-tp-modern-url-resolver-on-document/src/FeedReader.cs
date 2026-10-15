using System.Xml;

namespace Feed
{
    public class FeedReader
    {
        public XmlDocument Read(string body)
        {
            var resolver = new XmlUrlResolver
            {
                Credentials = System.Net.CredentialCache.DefaultCredentials
            };
            var doc = new XmlDocument();
~>            doc.XmlResolver = resolver;
            doc.LoadXml(body);
            return doc;
        }

        public XmlReader Open(string url)
        {
            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Parse,
~>                XmlResolver = new XmlUrlResolver(),
            };
            return XmlReader.Create(url, settings);
        }
    }
}
