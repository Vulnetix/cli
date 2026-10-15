package com.acme.repo;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SafeAccountController {
    @PersistenceContext
    private EntityManager em;

    @GetMapping("/accounts/safe")
    public List<Account> byEmail(@RequestParam("email") String email, @RequestParam("min") int min) {
        return em.createQuery(
                "SELECT a FROM Account a WHERE a.email = :email AND a.balance > ?1", Account.class)
            .setParameter("email", email)
            .setParameter(1, min)
            .getResultList();
    }
}
