using System.Xml;

public class Safe
{
    public XmlReaderSettings A()
    {
        return new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
    }
    public XmlReaderSettings B()
    {
        var s = new XmlReaderSettings();
        s.DtdProcessing = DtdProcessing.Ignore;
        if (s.DtdProcessing == DtdProcessing.Parse) { }
        return s;
    }
}
