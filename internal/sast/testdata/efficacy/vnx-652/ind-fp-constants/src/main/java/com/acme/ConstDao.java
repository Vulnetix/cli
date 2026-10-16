package com.acme;

import javax.xml.xquery.XQConnection;
import javax.xml.xquery.XQExpression;

public class ConstDao {
    private static final String BASE = "doc('catalog.xml')";
    private static final String ALL = BASE + "//item";

    public Object all(XQConnection conn) throws Exception {
        XQExpression expr = conn.createExpression();
        return expr.executeQuery(ALL);
    }

    public Object titles(XQConnection conn) throws Exception {
        XQExpression expr = conn.createExpression();
        return expr.executeQuery("doc('catalog.xml')" + "//item/title");
    }

    // expr.executeQuery("//a[@id='" + id + "']") was the old version
    public String note() {
        return "never call executeQuery(\"//a[@id='\" + id + \"']\") with request data";
    }
}
