package com.acme.directory;

import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchScope;
import javax.servlet.http.HttpServletRequest;

public class UnboundLookup {
    public int count(LDAPConnection conn, HttpServletRequest request) throws LDAPException {
        String group = request.getParameter("group");
~>        SearchResult r = conn.search("dc=acme,dc=com", SearchScope.SUB, "(memberOf=cn=" + group + ",ou=groups,dc=acme,dc=com)");
        return r.getEntryCount();
    }
}
