package com.acme.xml;

import javax.servlet.http.HttpServletRequest;
import javax.xml.xquery.XQConnection;
import javax.xml.xquery.XQExpression;
import javax.xml.xquery.XQResultSequence;

public class BookSearch {
    public XQResultSequence search(XQConnection conn, HttpServletRequest req) throws Exception {
        XQExpression expr = conn.createExpression();
~>        return expr.executeQuery("for $b in doc('books.xml')//book where $b/author = '" + req.getParameter("author") + "' return $b");
    }
}
