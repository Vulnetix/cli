package com.acme;

import javax.xml.namespace.QName;
import javax.xml.xquery.XQConnection;
import javax.xml.xquery.XQPreparedExpression;
import javax.xml.xquery.XQResultSequence;

public class SafeDao {
    private final XQConnection conn;

    public SafeDao(XQConnection conn) { this.conn = conn; }

    public XQResultSequence byAuthor(String author) throws Exception {
        XQPreparedExpression pe = conn.prepareExpression(
            "declare variable $author external; //book[author = $author]");
        pe.bindString(new QName("author"), author, null);
        return pe.executeQuery();
    }
}
