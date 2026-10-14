using System.IO;
using System.Xml;

namespace Feeds
{
    public class RssParser
    {
        public XmlReader Open(Stream upload)
        {
            var settings = new XmlReaderSettings();
~>            settings.DtdProcessing = DtdProcessing.Parse;
            settings.ValidationType = ValidationType.DTD;
            return XmlReader.Create(upload, settings);
        }

        public XmlTextReader Legacy(Stream upload)
        {
            var reader = new XmlTextReader(upload);
~>            reader.ProhibitDtd = false;
            return reader;
        }

        public XmlReader Inline(TextReader input)
        {
~>            return XmlReader.Create(input, new XmlReaderSettings { DtdProcessing = System.Xml.DtdProcessing.Parse });
        }
    }
}
