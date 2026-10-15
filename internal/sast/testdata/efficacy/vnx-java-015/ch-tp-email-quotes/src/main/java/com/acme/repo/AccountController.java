package com.acme.repo;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AccountController {
    @PersistenceContext
    private EntityManager em;

    @GetMapping("/accounts")
    public List<Account> byEmail(@RequestParam("email") String email) {
~>        return em.createQuery("SELECT a FROM Account a WHERE a.email = '" + email + "'", Account.class)
            .getResultList();
    }
}
