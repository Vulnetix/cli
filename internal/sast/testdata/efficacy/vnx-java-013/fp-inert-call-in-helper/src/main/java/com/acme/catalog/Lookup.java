package com.acme.catalog;

import java.util.List;
import javax.servlet.http.HttpServletRequest;
import org.dom4j.Document;
import org.dom4j.Node;

public class Lookup {
    // The request value goes into a helper that ignores it; what comes back is
    // a constant from a call into another class with literal arguments.
    List<Node> byDefaultCategory(HttpServletRequest req, Document catalog) throws Exception {
        String param = req.getParameter("cat");
        String cat = fixedCategory(req, param);
        return catalog.selectNodes("//item[@cat='" + cat + "']");
    }

    List<Node> byStockedTag(HttpServletRequest req, Document catalog) throws Exception {
        String param = req.getParameter("tag");
        Tags tags = TagsFactory.create();
        String tag = tags.nameOf("stocked");
        return catalog.selectNodes("//item[@tag='" + tag + "']");
    }

    private static String fixedCategory(HttpServletRequest req, String param) {
        String seen = param.trim();
        Categories categories = CategoriesFactory.create();
        String chosen = categories.byCode("TOOLS");
        return chosen;
    }
}
