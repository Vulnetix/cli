package com.acme;

import javax.naming.directory.*;
import javax.naming.NamingException;

public class DnSearch {
    private DirContext ctx;

    public boolean exists(String department) throws NamingException {
        SearchControls sc = new SearchControls();
~>        NamingEnumeration<SearchResult> r = ctx.search("ou=" + department + ",dc=acme,dc=com", "(objectClass=*)", sc);
        return r.hasMore();
    }
}
