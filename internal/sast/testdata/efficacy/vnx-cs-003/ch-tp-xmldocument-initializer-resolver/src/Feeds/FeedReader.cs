using System.Xml;

namespace News.Feeds;

public sealed class FeedReader
{
    public XmlDocument Parse(string body)
    {
        var doc = new XmlDocument
        {
~>            XmlResolver = new XmlUrlResolver(),
        };
        doc.LoadXml(body);
        return doc;
    }
}
