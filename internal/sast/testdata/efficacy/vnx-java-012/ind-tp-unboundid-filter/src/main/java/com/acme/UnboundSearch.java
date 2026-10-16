package com.acme;

import com.unboundid.ldap.sdk.*;
import javax.servlet.http.HttpServletRequest;

public class UnboundSearch {
    public SearchResult find(LDAPConnection conn, HttpServletRequest req) throws LDAPException {
        String mail = req.getParameter("mail");
        String expr = "(mail=" + mail + ")";
~>        SearchRequest sr = new SearchRequest("dc=acme,dc=com", SearchScope.SUB, expr, "cn");
        return conn.search(sr);
    }
}
