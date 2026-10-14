package com.acme.orders;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

import redis.clients.jedis.Jedis;

public class Datasources {

    public Connection orders(String user, char[] secret) throws SQLException {
~>        return DriverManager.getConnection("jdbc:mysql://10.0.4.12:3306/orders?useSSL=true", user, new String(secret));
    }

    public Connection reporting(String user, String secret) throws SQLException {
        String url =
~>            "jdbc:oracle:thin:@//reports-db.corp.acme.io:1521/REPORTS";
        return DriverManager.getConnection(url, user, secret);
    }

    public Jedis sessions() {
~>        return new Jedis("cache01.prod.acme.io", 6379);
    }
}
