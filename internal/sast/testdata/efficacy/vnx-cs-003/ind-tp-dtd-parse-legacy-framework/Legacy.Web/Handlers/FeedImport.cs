using System.IO;
using System.Xml;

namespace Legacy.Web.Handlers
{
    public class FeedImport
    {
        public int CountItems(Stream upload)
        {
            var settings = new XmlReaderSettings();
~>            settings.DtdProcessing = DtdProcessing.Parse;
            settings.IgnoreWhitespace = true;
            var count = 0;
            using (var reader = XmlReader.Create(upload, settings))
            {
                while (reader.Read())
                {
                    if (reader.IsStartElement("item")) count++;
                }
            }
            return count;
        }

        public void Legacy(TextReader text)
        {
~>            var reader = new XmlTextReader(text);
~>            reader.ProhibitDtd = false;
            while (reader.Read()) { }
        }
    }
}
