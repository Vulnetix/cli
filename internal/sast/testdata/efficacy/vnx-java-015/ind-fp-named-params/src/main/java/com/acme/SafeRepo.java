package com.acme;

import java.util.List;
import javax.persistence.EntityManager;
import org.springframework.web.bind.annotation.*;

@RestController
public class SafeRepo {
    private EntityManager em;

    @GetMapping("/safe")
    public List<User> byName(@RequestParam("name") String name) {
        return em.createQuery("SELECT u FROM User u WHERE u.name = :name", User.class)
                 .setParameter("name", name).getResultList();
    }
}
