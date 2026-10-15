package com.acme.xml;

import javax.xml.xquery.XQConnection;
import org.basex.api.client.ClientSession;

public class Stats {
    private static final String COUNT_ALL = "count(//order)";

    public Object total(XQConnection conn) throws Exception {
        String q = "count(//order[status='open'])";
        conn.createExpression().executeQuery(q);
        return conn.createExpression().executeQuery(COUNT_ALL);
    }

    public String byStatus(ClientSession session) throws Exception {
        return session.query("//order[status='" + "open" + "']").execute();
    }
}
