using System.IO;
using System.Xml;

namespace Billing
{
    public class StatementImporter
    {
        private readonly XmlDocument _template = new XmlDocument();

        public XmlDocument Import(Stream upload)
        {
            XmlDocument doc = new();
~>            doc.Load(upload);
            return doc;
        }

        public void LoadTemplate(string xml)
        {
~>            _template.LoadXml(xml);
        }

        public void LoadHardened(string xml)
        {
            XmlDocument safe = new() { XmlResolver = null };
            safe.LoadXml(xml);
        }
    }
}
