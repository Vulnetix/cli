package com.acme.directory;

import java.util.List;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.query.LdapQueryBuilder;
import org.springframework.web.bind.annotation.*;

@RestController
public class UserDirectory {
    private LdapTemplate ldapTemplate;

    @GetMapping("/users")
    public List<String> users(@RequestParam String name) {
        String filter = String.format("(cn=%s)", name);
~>        return ldapTemplate.search("ou=people", filter, (AttributesMapper<String>) a -> a.get("cn").toString());
    }

    @GetMapping("/groups")
    public Object groups(@RequestParam("group") String group) {
~>        return ldapTemplate.search(LdapQueryBuilder.query().filter("(cn=" + group + ")"), (AttributesMapper<String>) a -> "x");
    }
}
