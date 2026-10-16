using System.IO;
using System.Xml;

namespace Integration
{
    public class SoapEnvelopeReader
    {
        public XmlNode ReadBody(Stream payload)
        {
            var doc = new XmlDocument();
~>            doc.XmlResolver = new XmlUrlResolver();
            doc.Load(payload);
            return doc.DocumentElement?.FirstChild;
        }

        public string ReadTitle(Stream payload)
        {
            var resolver = new XmlUrlResolver();
            resolver.Credentials = System.Net.CredentialCache.DefaultCredentials;
            var reader = new XmlTextReader(payload);
~>            reader.XmlResolver = resolver;
            while (reader.Read())
            {
                if (reader.NodeType == XmlNodeType.Element && reader.Name == "title")
                {
                    return reader.ReadElementContentAsString();
                }
            }
            return null;
        }
    }
}
