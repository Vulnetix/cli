package com.acme;

import javax.naming.NamingException;
import javax.naming.directory.*;
import javax.servlet.http.HttpServletRequest;

public class SafeLdap {
    private DirContext ctx;

    public boolean login(HttpServletRequest request) throws NamingException {
        Object[] args = { request.getParameter("username") };
        SearchControls sc = new SearchControls();
        NamingEnumeration<SearchResult> r = ctx.search("ou=people,dc=acme,dc=com", "(&(objectClass=person)(uid={0}))", args, sc);
        return r.hasMore();
    }
}
