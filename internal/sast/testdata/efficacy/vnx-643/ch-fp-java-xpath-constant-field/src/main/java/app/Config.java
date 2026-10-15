package app;

import javax.xml.xpath.*;
import @@sample:o[r]g[.][w]3c[.]do[m][.]D[o]cu[m]en[t]@@;

public class Config {
    private static final String ROOT = "/config";
    private static final String SERVERS = ROOT + "/servers/server";
    private final XPath xpath = XPathFactory.newInstance().newXPath();

    public Object servers(Document doc) throws XPathExpressionException {
        return xpath.evaluate(SERVERS, doc, XPathConstants.NODESET);
    }

    public Object port(Document doc) throws XPathExpressionException {
        return xpath.compile(ROOT + "/port").evaluate(doc);
    }
}
