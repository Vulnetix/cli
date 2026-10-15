using System.IO;
using System.Xml;

namespace Acme.Services
{
    public class SafeImport
    {
        public XmlReader Open(Stream body)
        {
            var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
            settings.DtdProcessing = DtdProcessing.Ignore;
            if (settings.DtdProcessing == DtdProcessing.Parse)
            {
                throw new InvalidDataException("DTDs are not allowed");
            }
            var reader = new XmlTextReader(body);
            reader.ProhibitDtd = true;
            return XmlReader.Create(body, settings);
        }
    }
}
