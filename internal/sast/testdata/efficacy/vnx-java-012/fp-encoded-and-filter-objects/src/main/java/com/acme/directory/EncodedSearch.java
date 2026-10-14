package com.acme.directory;

import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.filter.AndFilter;
import org.springframework.ldap.filter.EqualsFilter;
import org.springframework.ldap.support.LdapEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
public class EncodedSearch {
    private LdapTemplate ldapTemplate;

    @GetMapping("/a")
    public Object a(@RequestParam String name) {
        String safe = LdapEncoder.filterEncode(name);
        Object r1 = ldapTemplate.search("ou=people", "(cn=" + safe + ")", (org.springframework.ldap.core.AttributesMapper<String>) x -> "");
        AndFilter filter = new AndFilter();
        filter.and(new EqualsFilter("objectclass", "person"));
        filter.and(new EqualsFilter("cn", name));
        Object r2 = ldapTemplate.search("ou=people", filter.encode(), (org.springframework.ldap.core.AttributesMapper<String>) x -> "");
        String encoded = new EqualsFilter("uid", name).encode();
        return ldapTemplate.search("ou=people", encoded, (org.springframework.ldap.core.AttributesMapper<String>) x -> "");
    }
}
