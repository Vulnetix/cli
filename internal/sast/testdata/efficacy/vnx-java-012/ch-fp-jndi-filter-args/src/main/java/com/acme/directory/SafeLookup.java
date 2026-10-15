package com.acme.directory;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.servlet.http.HttpServletRequest;

public class SafeLookup {
    public boolean exists(DirContext ctx, HttpServletRequest request) throws NamingException {
        String username = request.getParameter("username");
        NamingEnumeration<SearchResult> res = ctx.search("dc=acme,dc=com",
            "(&(objectClass=user)(sAMAccountName={0}))",
            new Object[] { username },
            new SearchControls());
        return res.hasMore();
    }
}
