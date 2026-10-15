package com.acme.directory;

import java.util.List;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import static org.springframework.ldap.query.LdapQueryBuilder.query;

@RestController
public class PeopleRepo {
    private final LdapTemplate ldapTemplate;

    public PeopleRepo(LdapTemplate t) {
        this.ldapTemplate = t;
    }

    @GetMapping("/people/by-uid")
    public List<String> byUid(@RequestParam String uid) {
        AttributesMapper<String> mapper = a -> (String) a.get("cn").get();
        return ldapTemplate.search(
            query().base("ou=people").where("objectclass").is("person").and("uid").is(uid),
            mapper);
    }
}
