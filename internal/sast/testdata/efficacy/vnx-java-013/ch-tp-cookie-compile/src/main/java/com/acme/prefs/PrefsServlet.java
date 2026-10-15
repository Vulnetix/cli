package com.acme.prefs;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;
import @@sample:o[r]g[.][w]3c[.]do[m][.]D[o]cu[m]en[t]@@;

public class PrefsServlet {
    private Document prefs;

    public String theme(HttpServletRequest req) throws Exception {
        String user = "anonymous";
        for (Cookie c : req.getCookies()) {
            if ("user".equals(c.getName())) {
                user = c.getValue();
            }
        }
        XPath xp = XPathFactory.newInstance().newXPath();
~>        XPathExpression e = xp.compile("//user[@name='" + user + "']/theme");
        return e.evaluate(prefs);
    }
}
