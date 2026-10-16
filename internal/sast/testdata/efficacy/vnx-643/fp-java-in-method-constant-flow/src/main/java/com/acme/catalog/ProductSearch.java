package com.acme.catalog;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import org.w3c.dom.Document;

public class ProductSearch {

    private final XPath xpath = XPathFactory.newInstance().newXPath();

    // The request value is read, but the branch that would use it can never run.
    public String featured(HttpServletRequest request, Document catalog) throws Exception {
        String sku = request.getParameter("sku");
        int threshold = 12;
        String pick;
        if ((threshold * 4) - 10 > 30) pick = "FEATURED-1";
        else pick = sku;
        String expr = "/catalog/product[@sku='" + pick + "']/name";
        return xpath.evaluate(expr, catalog);
    }

    // A conditional expression whose condition folds to true.
    public String banner(HttpServletRequest request, Document catalog) throws Exception {
        String region = request.getHeader("X-Region");
        int limit = 50;
        String code = limit * 2 > 60 ? "eu-west" : region;
        return xpath.evaluate("/catalog/banner[@region='" + code + "']", catalog);
    }

    // The map holds the request value under one key; the query reads another.
    public String category(HttpServletRequest request, Document catalog) throws Exception {
        String wanted = request.getParameter("category");
        Map<String, String> labels = new HashMap<String, String>();
        labels.put("default", "hardware");
        labels.put("requested", wanted);
        String label = labels.get("default");
        return xpath.evaluate("/catalog/category[@name='" + label + "']/count", catalog);
    }

    // The list element read back is the literal still at that index.
    public String vendor(HttpServletRequest request, Document catalog) throws Exception {
        String supplied = request.getParameter("vendor");
        List<String> names = new ArrayList<String>();
        names.add("ignored");
        names.add(supplied);
        names.add("acme");
        names.remove(0);
        String vendor = names.get(1);
        return xpath.evaluate("/catalog/vendor[@id='" + vendor + "']", catalog);
    }

    // A switch on a constant selects a case that assigns a literal.
    public String tier(HttpServletRequest request, Document catalog) throws Exception {
        String fromUser = request.getParameter("tier");
        int level = 2;
        String tier;
        switch (level) {
            case 1:
                tier = fromUser;
                break;
            case 2:
                tier = "gold";
                break;
            default:
                tier = fromUser;
                break;
        }
        return xpath.evaluate("/catalog/tier[@name='" + tier + "']", catalog);
    }

    // A helper of this file that ignores its argument and returns a constant.
    public String shelf(HttpServletRequest request, Document catalog) throws Exception {
        String raw = request.getParameter("shelf");
        String shelf = new Layout().defaultShelf(raw);
        return xpath.evaluate("/catalog/shelf[@id='" + shelf + "']", catalog);
    }

    static class Layout {
        String defaultShelf(String requested) {
            String fallback = "A1";
            return fallback;
        }
    }
}
