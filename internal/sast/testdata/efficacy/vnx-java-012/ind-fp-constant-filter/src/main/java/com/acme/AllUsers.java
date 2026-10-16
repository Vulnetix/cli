package com.acme;

import javax.naming.NamingException;
import javax.naming.directory.*;

public class AllUsers {
    private static final String FILTER = "(objectClass=inetOrgPerson)";
    private DirContext ctx;

    public NamingEnumeration<SearchResult> all() throws NamingException {
        return ctx.search("ou=people,dc=acme,dc=com", FILTER, new SearchControls());
    }
}
