package com.acme;

import javax.xml.xquery.XQConnection;
import javax.xml.xquery.XQExpression;
import javax.xml.xquery.XQResultSequence;

public class BookDao {
    private final XQConnection conn;

    public BookDao(XQConnection conn) { this.conn = conn; }

    public XQResultSequence byAuthor(String author) throws Exception {
        XQExpression expr = conn.createExpression();
~>        return expr.executeQuery("for $b in doc('books.xml')//book where $b/author = '" + author + "' return $b");
    }
}
