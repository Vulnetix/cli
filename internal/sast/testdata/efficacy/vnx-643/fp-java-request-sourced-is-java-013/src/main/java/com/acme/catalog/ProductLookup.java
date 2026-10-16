package com.acme.catalog;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import org.w3c.dom.Document;

public class ProductLookup {

    private final XPath xpath = XPathFactory.newInstance().newXPath();

    // The folded condition is false: the request value is the one used.
    public String featured(HttpServletRequest request, Document catalog) throws Exception {
        String sku = request.getParameter("sku");
        int threshold = 3;
        String pick;
        if ((threshold * 4) - 10 > 30) pick = "FEATURED-1";
        else pick = sku;
        String expr = "/catalog/product[@sku='" + pick + "']/name";
        return xpath.evaluate(expr, catalog);
    }

    // A condition on run-time data cannot be folded: either side may run.
    public String banner(HttpServletRequest request, Document catalog) throws Exception {
        String region = request.getHeader("X-Region");
        String code = region.length() > 2 ? "eu-west" : region;
        return xpath.evaluate("/catalog/banner[@region='" + code + "']", catalog);
    }

    // The key read back is the one holding the request value.
    public String category(HttpServletRequest request, Document catalog) throws Exception {
        String wanted = request.getParameter("category");
        Map<String, String> labels = new HashMap<String, String>();
        labels.put("default", "hardware");
        labels.put("requested", wanted);
        String label = labels.get("requested");
        return xpath.evaluate("/catalog/category[@name='" + label + "']/count", catalog);
    }

    // After remove(0) the request value sits at index 0.
    public String vendor(HttpServletRequest request, Document catalog) throws Exception {
        String supplied = request.getParameter("vendor");
        List<String> names = new ArrayList<String>();
        names.add("ignored");
        names.add(supplied);
        names.add("acme");
        names.remove(0);
        String vendor = names.get(0);
        return xpath.evaluate("/catalog/vendor[@id='" + vendor + "']", catalog);
    }

    // The constant selects the case that assigns the request value.
    public String tier(HttpServletRequest request, Document catalog) throws Exception {
        String fromUser = request.getParameter("tier");
        int level = 1;
        String tier;
        switch (level) {
            case 1:
                tier = fromUser;
                break;
            case 2:
                tier = "gold";
                break;
            default:
                tier = "bronze";
                break;
        }
        return xpath.evaluate("/catalog/tier[@name='" + tier + "']", catalog);
    }

    // The helper returns a transform of its parameter.
    public String shelf(HttpServletRequest request, Document catalog) throws Exception {
        String raw = request.getParameter("shelf");
        String shelf = new Layout().normalise(raw);
        return xpath.evaluate("/catalog/shelf[@id='" + shelf + "']", catalog);
    }

    static class Layout {
        String normalise(String requested) {
            return requested.trim().toUpperCase();
        }
    }
}
