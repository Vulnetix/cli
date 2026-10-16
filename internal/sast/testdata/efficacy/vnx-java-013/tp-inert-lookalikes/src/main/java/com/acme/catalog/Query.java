package com.acme.catalog;

import java.util.List;
import javax.servlet.http.HttpServletRequest;
import org.dom4j.Document;
import org.dom4j.Node;

public class Query {
    // The same helper shapes with the request value in the way.
    List<Node> argumentIsRequestValue(HttpServletRequest req, Document catalog) throws Exception {
        String param = req.getParameter("tag");
        Tags tags = TagsFactory.create();
        String tag = tags.nameOf(param);
~>        return catalog.selectNodes("//item[@tag='" + tag + "']");
    }

    List<Node> receiverBuiltFromRequest(HttpServletRequest req, Document catalog) throws Exception {
        Tags tags = new Tags(req.getParameter("scope"));
        String tag = tags.nameOf("stocked");
~>        return catalog.selectNodes("//item[@tag='" + tag + "']");
    }

    List<Node> receiverFedRequestValue(HttpServletRequest req, Document catalog) throws Exception {
        Tags tags = TagsFactory.create();
        tags.add(req.getParameter("extra"));
        String tag = tags.nameOf("stocked");
~>        return catalog.selectNodes("//item[@tag='" + tag + "']");
    }

    List<Node> helperHandsBackItsArgument(HttpServletRequest req, Document catalog) throws Exception {
        String param = req.getParameter("cat");
        String cat = categoryFor(req, param);
~>        return catalog.selectNodes("//item[@cat='" + cat + "']");
    }

    private static String categoryFor(HttpServletRequest req, String param) {
        Categories categories = CategoriesFactory.create();
        String chosen = categories.byCode(param);
        return chosen;
    }
}
