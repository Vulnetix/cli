package com.acme.repo;

import java.util.List;
import javax.persistence.EntityManager;

public class UserRepositoryImpl {
    private EntityManager em;

    public List<User> findByEmail(String email) {
~>        return em.createQuery("select u from User u where u.email = '" + email + "'", User.class)
            .getResultList();
    }

    public User findByLogin(final String login) {
        StringBuilder q = new StringBuilder("select u from User u where u.login = '");
        q.append(login).append("'");
        String jpql = "select u from User u where u.name = '" + login + "' and u.active = true";
~>        return em.createQuery(jpql, User.class).getSingleResult();
    }
}
