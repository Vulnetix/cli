package com.acme.xml;

import javax.xml.namespace.QName;
import javax.xml.xquery.XQConnection;
import javax.xml.xquery.XQPreparedExpression;

public class BookSearch {
    private static final String BOOKS = "doc('books.xml')//book";

    public Object search(XQConnection conn, String author) throws Exception {
        XQPreparedExpression pe = conn.prepareExpression(
            "declare variable $author external; " + BOOKS + "[author = $author]");
        pe.bindString(new QName("author"), author, null);
        return pe.executeQuery();
    }
}
