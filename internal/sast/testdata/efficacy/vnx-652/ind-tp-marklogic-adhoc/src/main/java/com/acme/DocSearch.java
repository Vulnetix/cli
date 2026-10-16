package com.acme;

import com.marklogic.xcc.AdhocQuery;
import com.marklogic.xcc.Session;
import javax.servlet.http.HttpServletRequest;

public class DocSearch {
    public Object run(Session session, HttpServletRequest req) throws Exception {
        String term = req.getParameter("q");
~>        AdhocQuery q = session.newAdhocQuery("cts:search(/doc, cts:word-query('" + term + "'))");
        return session.submitRequest(q);
    }
}
