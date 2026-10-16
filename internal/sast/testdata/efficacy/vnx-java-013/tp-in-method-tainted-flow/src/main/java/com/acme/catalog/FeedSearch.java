package com.acme.catalog;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import org.w3c.dom.Document;

public class FeedSearch {
    private Document feed;
    private final XPath xp = XPathFactory.newInstance().newXPath();

    // 60 / 4 > 20 is false: the request value is the one evaluated.
    public String channel(HttpServletRequest request) throws Exception {
        String requested = request.getParameter("channel");
        int limit = 60;
        String channel;
        if (limit / 4 > 20) channel = "news";
        else channel = requested;
        String expr = "/rss/channel[@id='" + channel + "']/title";
~>        return xp.evaluate(expr, feed);
    }

    public String item(HttpServletRequest request) throws Exception {
        String guid = request.getParameter("guid");
        int mode = 1;
        String key = mode == 0 ? "latest" : guid;
~>        return xp.evaluate("/rss/channel/item[@key='" + key + "']/link", feed);
    }

    public String field(HttpServletRequest request) throws Exception {
        String custom = request.getParameter("field");
        String layout = "full";
        String node;
        switch (layout.charAt(0)) {
            case 'c':
                node = "title";
                break;
            case 'f':
                node = custom;
                break;
            default:
                node = "link";
                break;
        }
~>        return xp.evaluate("/rss/channel/item[1]/*[name()='" + node + "']", feed);
    }

    public String tagged(HttpServletRequest request) throws Exception {
        List<String> tags = new ArrayList<String>();
        tags.add(request.getParameter("tag"));
        tags.add("featured");
        String tag = tags.get(0);
~>        return xp.evaluate("//item[category='" + tag + "']/title", feed);
    }

    public String localized(HttpServletRequest request) throws Exception {
        Map<String, String> langs = new HashMap<String, String>();
        langs.put("default", "en");
        langs.put("user", request.getHeader("Accept-Language"));
        String lang = langs.get("user");
~>        return xp.evaluate("//item[@lang='" + lang + "']/title", feed);
    }

    public String section(HttpServletRequest request) throws Exception {
        String name = request.getParameter("section");
        String id = sectionId(name);
~>        return xp.evaluate("//section[@id='" + id + "']", feed);
    }

    private String sectionId(String name) {
        return name.trim().toLowerCase();
    }
}
