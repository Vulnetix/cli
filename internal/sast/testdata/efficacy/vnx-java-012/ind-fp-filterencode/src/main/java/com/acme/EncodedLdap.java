package com.acme;

import javax.servlet.http.HttpServletRequest;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.support.LdapEncoder;

public class EncodedLdap {
    private LdapTemplate ldapTemplate;

    public Object find(HttpServletRequest request) {
        String safe = LdapEncoder.filterEncode(request.getParameter("uid"));
        String filter = "(&(objectClass=person)(uid=" + safe + "))";
        return ldapTemplate.search("ou=people", filter, (org.springframework.ldap.core.AttributesMapper<Object>) a -> a);
    }
}
