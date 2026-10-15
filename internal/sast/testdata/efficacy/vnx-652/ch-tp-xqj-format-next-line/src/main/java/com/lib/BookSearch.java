package com.lib;

import javax.xml.xquery.XQConnection;
import javax.xml.xquery.XQPreparedExpression;
import javax.xml.xquery.XQResultSequence;

public class BookSearch {
    public XQResultSequence byAuthor(XQConnection conn, String author) throws Exception {
~>        XQPreparedExpression expr = conn.prepareExpression(
                String.format("for $b in doc('books.xml')//book[author='%s'] return $b", author));
        return expr.executeQuery();
    }
}
