package com.acme.auth;

import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import org.springframework.ldap.support.LdapEncoder;

public class SafeAuthenticator {
    private DirContext ctx;

    public Object lookup(String username, String baseDn) throws Exception {
        String filter = "(uid=" + LdapEncoder.filterEncode(username) + ")";
        return ctx.search(baseDn, filter, new SearchControls());
    }
}
