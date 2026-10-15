using System.IO;
using System.Xml;

namespace Legacy
{
    public class OrderParser
    {
        public XmlDocument Load(Stream input)
        {
            XmlDocument doc = new XmlDocument();
            doc.XmlResolver = null;
            doc.Load(input);
            return doc;
        }

        public string Read(Stream input)
        {
            XmlTextReader reader = new XmlTextReader(input);
            reader.DtdProcessing = DtdProcessing.Prohibit;
            reader.Read();
            return reader.Value;
        }
    }
}
