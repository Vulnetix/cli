package com.acme.directory;

import java.util.List;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import static org.springframework.ldap.query.LdapQueryBuilder.query;

@RestController
public class PeopleController {
    private final LdapTemplate ldapTemplate;

    public PeopleController(LdapTemplate t) {
        this.ldapTemplate = t;
    }

    @GetMapping("/people")
    public List<String> find(@RequestParam("uid") String uid, @RequestParam("cn") String cn) {
        AttributesMapper<String> mapper = attrs -> (String) attrs.get("cn").get();
~>        List<String> byUid = ldapTemplate.search("ou=people", "(uid=" + uid + ")", mapper);
~>        List<String> byCn = ldapTemplate.search(query().filter("(cn=" + cn + ")"), mapper);
        byUid.addAll(byCn);
        return byUid;
    }
}
