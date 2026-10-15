using System.IO;
using System.Xml;

namespace Acme.Services
{
    public class ImportService
    {
        public XmlReader Open(Stream body)
        {
            var settings = new XmlReaderSettings();
~>            settings.DtdProcessing = DtdProcessing.Parse;
            return XmlReader.Create(body, settings);
        }

        public XmlReader OpenInline(Stream body)
        {
~>            var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse, MaxCharactersFromEntities = 0 };
            return XmlReader.Create(body, settings);
        }

        public XmlTextReader Legacy(TextReader text)
        {
            var reader = new XmlTextReader(text);
~>            reader.ProhibitDtd = false;
            return reader;
        }
    }
}
