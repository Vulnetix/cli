package com.acme.repo;

import java.util.List;
import javax.persistence.EntityManager;
import org.springframework.web.bind.annotation.*;

@RestController
public class SafeRepository {
    private EntityManager em;

    @GetMapping("/users")
    public List<User> users(@RequestParam String email, @RequestParam int page) {
        return em.createQuery("select u from User u where u.email = :email", User.class)
            .setParameter("email", email)
            .setFirstResult(page * 20)
            .getResultList();
    }

    public List<User> byName(String name) {
        return em.createQuery("select u from User u where u.name = ?1", User.class)
            .setParameter(1, name)
            .getResultList();
    }

    public User byId(String id) {
        return em.createNamedQuery("User.byId", User.class).setParameter("id", id).getSingleResult();
    }
}
