package com.acme.cfg;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;

public class ConfigReader {
    private static final String ROOT = "/config";
    private final XPath xpath = XPathFactory.newInstance().newXPath();

    public String port(Document doc) throws Exception {
        String expr = ROOT + "/server/port";
        String host = xpath.evaluate(ROOT + "/server/host", doc);
        log.info("host " + host);
        return xpath.compile(expr).evaluate(doc);
    }

    public int count(Document doc) throws Exception {
        return Integer.parseInt(xpath.evaluate("count(/config/server)", doc));
    }

    public Object compute(ScriptEngine engine, String a) throws Exception {
        return engine.eval("1 + " + a);
    }
}
