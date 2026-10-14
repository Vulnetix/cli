package com.acme.docs;

import javax.servlet.http.HttpServletRequest;
import javax.xml.xpath.XPath;

public class XPathNotes {
    String note(HttpServletRequest request) {
        String id = request.getParameter("id");
        // xp.evaluate("//user[@id='" + id + "']", doc) is injectable
        String hint = "never xpath.evaluate(\"//u[@id='\" + id + \"']\")";
        log("xpath.compile(expr) refused for " + id);
        return hint;
    }

    void log(String s) {
    }
}
