using System.IO;
using System.Xml;

namespace Legacy.Api.Xml
{
    public static class SafeXml
    {
        private static readonly string Template = "<root><item/></root>";

        public static XmlDocument Load(Stream input)
        {
            var doc = new XmlDocument();
            doc.XmlResolver = null;
            doc.Load(input);
            return doc;
        }

        public static XmlDocument Initialized(Stream input)
        {
            var doc = new XmlDocument { XmlResolver = null };
            doc.Load(input);
            return doc;
        }

        public static XmlReader Reader(Stream input)
        {
            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = new XmlUrlResolver(),
            };
            return XmlReader.Create(input, settings);
        }

        public static XmlReader Ignored(Stream input)
        {
            var settings = new XmlReaderSettings();
            settings.DtdProcessing = DtdProcessing.Ignore;
            settings.XmlResolver = null;
            return XmlReader.Create(input, settings);
        }

        public static XmlTextReader Text(Stream input)
        {
            var reader = new XmlTextReader(input);
            reader.DtdProcessing = DtdProcessing.Prohibit;
            return reader;
        }

        public static XmlTextReader Strict(Stream input)
        {
            var reader = new XmlTextReader(input) { ProhibitDtd = true };
            return reader;
        }

        public static XmlReader ParsedNoResolver(Stream input)
        {
            var settings = new XmlReaderSettings();
            settings.DtdProcessing = DtdProcessing.Parse;
            settings.XmlResolver = null;
            return XmlReader.Create(input, settings);
        }

        public static XmlDocument FromTemplate()
        {
            var doc = new XmlDocument();
            doc.LoadXml(Template);
            doc.LoadXml("<empty/>");
            return doc;
        }
    }
}
