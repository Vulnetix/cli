package com.acme.directory;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.servlet.http.HttpServletRequest;

public class GroupListing {
    private static final String GROUP_FILTER = "(objectClass=groupOfNames)";

    public int page(DirContext ctx, HttpServletRequest request) throws NamingException {
        int page = Integer.parseInt(request.getParameter("page"));
        SearchControls sc = new SearchControls();
        sc.setCountLimit(50L * page);
        NamingEnumeration<SearchResult> res = ctx.search("ou=groups,dc=acme,dc=com", GROUP_FILTER, sc);
        int n = 0;
        while (res.hasMore()) { res.next(); n++; }
        return n;
    }
}
