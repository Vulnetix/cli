package com.acme.directory;

import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchScope;
import javax.servlet.http.HttpServletRequest;

public class UnboundLookup {
    Object lookup(LDAPConnection conn, HttpServletRequest req) throws Exception {
        String uid = req.getHeader("X-User");
~>        Filter f = Filter.create("(uid=" + uid + ")");
~>        SearchRequest sr = new SearchRequest("dc=acme,dc=com", SearchScope.SUB, "(cn=" + uid + ")");
~>        return conn.search("dc=acme,dc=com", SearchScope.SUB, "(mail=" + req.getParameter("m") + ")");
    }
}
