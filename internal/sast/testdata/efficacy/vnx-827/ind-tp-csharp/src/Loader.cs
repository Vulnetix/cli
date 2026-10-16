using System.Xml;

public class Loader
{
    public XmlReaderSettings Make()
    {
        var settings = new XmlReaderSettings
        {
~>            DtdProcessing = DtdProcessing.Parse,
            XmlResolver = null
        };
        return settings;
    }

    public void Legacy(XmlTextReader r)
    {
~>        r.ProhibitDtd = false;
    }
}
