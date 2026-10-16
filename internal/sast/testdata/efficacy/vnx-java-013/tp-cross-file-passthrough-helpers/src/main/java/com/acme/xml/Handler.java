package com.acme.xml;

import javax.xml.xpath.XPath;
import javax.servlet.http.HttpServletRequest;
import org.w3c.dom.Document;

public class Handler {
    private XPath xpath;
    private Document doc;

    public void echoed(HttpServletRequest request) throws Exception {
        String param = request.getParameter("value");
        Echo echo = new Echo();
        String value = echo.same(param);
~>        xpath.evaluate("//user[@id='" + value + "']", doc);
~>        xpath.evaluate("//user[@id='" + echo.same(param) + "']", doc);
    }

    public void stored(HttpServletRequest request) throws Exception {
        Slot slot = new Slot(request.getParameter("value"));
        String value = slot.value();
~>        xpath.evaluate("//user[@id='" + value + "']", doc);
    }

    public void storedFromLocal(HttpServletRequest request) throws Exception {
        String param = request.getParameter("value");
        Slot slot = new Slot(param);
~>        xpath.evaluate("//user[@id='" + slot.value() + "']", doc);
    }

    public void replaced(HttpServletRequest request) throws Exception {
        MutableSlot slot = new MutableSlot("report");
        slot.put(request.getParameter("value"));
        String value = slot.value();
~>        xpath.evaluate("//user[@id='" + value + "']", doc);
    }

    public void ambiguousClass(HttpServletRequest request) throws Exception {
        com.acme.xml.left.Names names = new com.acme.xml.left.Names();
        String param = request.getParameter("value");
        String value = names.pick(param);
~>        xpath.evaluate("//user[@id='" + value + "']", doc);
    }

    public void unknownClass(HttpServletRequest request) throws Exception {
        String param = request.getParameter("value");
        String value = Registry.lookup(param);
~>        xpath.evaluate("//user[@id='" + value + "']", doc);
    }

    public void chained(HttpServletRequest request) throws Exception {
        String param = request.getParameter("value");
        Pad pad = new Pad();
        Echo echo = new Echo();
        String value = pad.keep(echo.same(param));
~>        xpath.evaluate("//user[@id='" + value + "']", doc);
    }

    public void secondArgument(HttpServletRequest request) throws Exception {
        String param = request.getParameter("value");
        Cleaner cleaner = new Cleaner();
        String value = cleaner.choose("fixed", param);
~>        xpath.evaluate("//user[@id='" + value + "']", doc);
    }
}
