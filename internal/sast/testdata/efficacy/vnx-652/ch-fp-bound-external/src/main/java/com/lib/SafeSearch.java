package com.lib;

import javax.xml.namespace.QName;
import javax.xml.xquery.*;

public class SafeSearch {
    XQResultSequence find(XQConnection conn, String title) throws XQException {
        String q = "declare variable $t external; "
                + "for $b in doc('books.xml')//book[title=$t] return $b";
        XQPreparedExpression expr = conn.prepareExpression(q);
        expr.bindString(new QName("t"), title, null);
        // conn.prepareExpression("//book[title='" + title + "']") was unsafe
        return expr.executeQuery();
    }
}
