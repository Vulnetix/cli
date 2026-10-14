package com.acme.web;

import java.util.List;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import org.springframework.web.bind.annotation.*;

@RestController
public class OrderController {
    @PersistenceContext
    private EntityManager em;

    @GetMapping("/orders")
    public List<?> orders(@RequestParam("status") String status) {
~>        return em.createQuery("SELECT o FROM Order o WHERE o.status = '" + status + "'").getResultList();
    }

    @GetMapping("/orders/sorted")
    public List<?> sorted(@RequestParam String sort) {
        String jpql = "SELECT o FROM Order o ORDER BY o." + sort;
~>        return em.createQuery(jpql, Order.class).getResultList();
    }
}
