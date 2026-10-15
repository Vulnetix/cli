using System.IO;
using System.Xml;

namespace Legacy
{
    public class InvoiceParser
    {
        public string Total(Stream input)
        {
~>            XmlTextReader reader = new XmlTextReader(input);
            while (reader.Read())
            {
                if (reader.Name == "total") return reader.ReadElementContentAsString();
            }
            return null;
        }
    }
}
