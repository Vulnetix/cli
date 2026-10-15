package com.lib;

import javax.xml.xquery.*;

public class UserLookup {
    public XQResultSequence find(XQExpression expr, String userName) throws XQException {
        String q = "for $u in collection('users')//user";
        q += " where $u/name = '" + userName + "' return $u";
~>        return expr.executeQuery(q);
    }
}
