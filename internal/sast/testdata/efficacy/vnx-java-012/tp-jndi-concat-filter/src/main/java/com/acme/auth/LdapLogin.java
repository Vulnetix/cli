package com.acme.auth;

import javax.naming.NamingEnumeration;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.servlet.http.HttpServletRequest;

public class LdapLogin {
    private DirContext ctx;

    boolean login(HttpServletRequest request) throws Exception {
        String user = request.getParameter("user");
        String pass = request.getParameter("pass");
        String filter = "(&(uid=" + user + ")(userPassword=" + pass + "))";
        SearchControls sc = new SearchControls();
        sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
~>        NamingEnumeration<SearchResult> results = ctx.search("ou=people,dc=acme,dc=com", filter, sc);
        return results.hasMore();
    }
}
