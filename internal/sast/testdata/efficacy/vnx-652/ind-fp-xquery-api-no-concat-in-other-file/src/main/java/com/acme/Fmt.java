package com.acme;

import javax.xml.xquery.XQConnection;

public class Fmt {
    public String label(String name) {
        return String.format("Hello %s", name);
    }

    public Object fixed(XQConnection conn) throws Exception {
        return conn.createExpression().executeQuery("count(doc('a.xml')//x)");
    }
}
