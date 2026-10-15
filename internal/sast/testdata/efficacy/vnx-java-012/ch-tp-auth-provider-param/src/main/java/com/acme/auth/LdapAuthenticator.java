package com.acme.auth;

import javax.naming.NamingEnumeration;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

public class LdapAuthenticator {
    private DirContext ctx;

    public boolean authenticate(String username, String password) throws Exception {
        String filter = "(&(objectClass=inetOrgPerson)(uid=" + username + "))";
        SearchControls sc = new SearchControls();
        sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
~>        NamingEnumeration<SearchResult> res = ctx.search("ou=people,dc=acme,dc=com", filter, sc);
        return res.hasMore();
    }
}
