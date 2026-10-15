package com.acme.repo;

import java.sql.*;

public class UserDao {
    ResultSet find(Connection c, String q) throws SQLException {
        PreparedStatement ps = c.prepareStatement("SELECT * FROM users WHERE email LIKE ?");
~>        ps.setString(1, "%" + q + "%");
        return ps.executeQuery();
    }

    Query byName(EntityManager em, String n) {
        Query query = em.createQuery("select u from User u where u.name like :n");
~>        query.setParameter("n", "%" + n);
        return query;
    }
}
