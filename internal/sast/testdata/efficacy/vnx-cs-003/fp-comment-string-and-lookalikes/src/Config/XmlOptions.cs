using System;
using System.Xml;

namespace Config
{
    public class XmlOptions
    {
        public DtdProcessing Mode { get; set; } = DtdProcessing.Prohibit; // never Parse untrusted input

        public void Apply(XmlReaderSettings settings, string configured)
        {
            // doc.XmlResolver = new XmlUrlResolver();
            Console.WriteLine("DtdProcessing.Parse and XmlUrlResolver enable XXE");
            settings.DtdProcessing = Enum.Parse<DtdProcessing>(configured == "strict" ? "Prohibit" : "Ignore");
            if (settings.XmlResolver == null)
            {
                Console.WriteLine("resolver disabled");
            }
            var legacy = new LegacyFlags { ProhibitDtd = true, AllowFalse = false };
        }
    }
}
