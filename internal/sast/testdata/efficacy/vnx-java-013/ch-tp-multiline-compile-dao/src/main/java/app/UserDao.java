package app;

import javax.xml.xpath.*;
import @@sample:o[r]g[.][w]3c[.]do[m][.]D[o]cu[m]en[t]@@;
import @@sample:o[r]g[.][w]3c[.]do[m][.]N[o]de[L]is[t]@@;

public class UserDao {
    private final XPath xpath = XPathFactory.newInstance().newXPath();

    public NodeList find(Document doc, String name) throws XPathExpressionException {
~>        XPathExpression expr = xpath.compile(
                "//user[name/text()='" + name + "']");
        return (NodeList) expr.evaluate(doc, XPathConstants.NODESET);
    }
}
