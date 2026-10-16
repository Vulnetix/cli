package com.acme.xml;

import javax.xml.xpath.XPath;
import javax.servlet.http.HttpServletRequest;
import org.w3c.dom.Document;

public class Handler {
    private XPath xpath;
    private Document doc;

    public void sanitized(HttpServletRequest request) throws Exception {
        String param = request.getParameter("value");
        Cleaner cleaner = new Cleaner();
        String value = cleaner.clean(param);
        xpath.evaluate("//user[@id='" + value + "']", doc);
    }

    public void sanitizedInline(HttpServletRequest request) throws Exception {
        Cleaner cleaner = new Cleaner();
        String value = cleaner.clean(request.getParameter("value"));
        xpath.evaluate("//user[@id='" + value + "']", doc);
    }

    public void settings() throws Exception {
        Settings settings = new Settings();
        String value = settings.name();
        xpath.evaluate("//user[@id='" + value + "']", doc);
        xpath.evaluate("//user[@id='" + Settings.fixed() + "']", doc);
        xpath.evaluate("//user[@id='" + settings.ext() + "']", doc);
    }

    public void storedLiteral() throws Exception {
        Slot slot = new Slot("report");
        String value = slot.value();
        xpath.evaluate("//user[@id='" + value + "']", doc);
    }

    public void chained(HttpServletRequest request) throws Exception {
        Settings settings = new Settings();
        Pad pad = new Pad();
        String value = pad.keep(pad.keep(settings.name()));
        xpath.evaluate("//user[@id='" + value + "']", doc);
        String second = new Cleaner().choose(request.getParameter("value"), "fixed");
        xpath.evaluate("//user[@id='" + second + "']", doc);
    }
}
