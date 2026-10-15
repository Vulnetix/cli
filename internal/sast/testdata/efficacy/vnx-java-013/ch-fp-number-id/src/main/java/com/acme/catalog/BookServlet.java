package com.acme.catalog;

import javax.servlet.http.HttpServletRequest;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import @@sample:o[r]g[.][w]3c[.]do[m][.]D[o]cu[m]en[t]@@;

public class BookServlet {
    private Document doc;

    public String title(HttpServletRequest req) throws Exception {
        int id = Integer.parseInt(req.getParameter("id"));
        XPath xp = XPathFactory.newInstance().newXPath();
        return xp.evaluate("/catalog/book[@id=" + id + "]/title", doc);
    }
}
