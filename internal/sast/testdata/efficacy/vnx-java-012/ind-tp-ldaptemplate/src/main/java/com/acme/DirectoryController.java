package com.acme;

import java.util.List;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.web.bind.annotation.*;

@RestController
public class DirectoryController {
    private final LdapTemplate ldapTemplate;
    DirectoryController(LdapTemplate t) { this.ldapTemplate = t; }

    @GetMapping("/people")
    public List<String> find(@RequestParam("cn") String cn) {
~>        return ldapTemplate.search("ou=people", "(cn=" + cn + ")", (org.springframework.ldap.core.AttributesMapper<String>) a -> a.get("cn").get().toString());
    }
}
