package com.acme.xml;

import javax.xml.xquery.XQConnection;
import javax.xml.xquery.XQPreparedExpression;

public class UserLookup {
    public Object find(XQConnection conn, String username) throws Exception {
        String query = "doc('users.xml')/users/user[name='" + username + "']";
~>        XQPreparedExpression pe = conn.prepareExpression(query);
        return pe.executeQuery();
    }

    public Object byId(XQConnection conn, String id) throws Exception {
        String q = "doc('users.xml')//user[@id=" +
            id + "]";
~>        return conn.createExpression().executeQuery(q);
    }
}
