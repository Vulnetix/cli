package com.acme;

import java.util.List;
import javax.persistence.EntityManager;
import org.springframework.web.bind.annotation.*;

@RestController
public class UserRepo {
    private EntityManager em;

    @GetMapping("/users")
    public List<User> byName(@RequestParam("name") String name) {
~>        return em.createQuery("SELECT u FROM User u WHERE u.name = '" + name + "'", User.class).getResultList();
    }
}
