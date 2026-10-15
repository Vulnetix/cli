package com.acme.xml;

import com.marklogic.xcc.AdhocQuery;
import com.marklogic.xcc.Session;

public class SearchService {
    public AdhocQuery build(Session session, String term) {
~>        AdhocQuery q = session.newAdhocQuery(
            "cts:search(fn:doc(), cts:word-query('" + term + "'))");
        return q;
    }
}
