package com.acme.report;

import java.sql.Connection;
import java.sql.DriverManager;
import javax.mail.PasswordAuthentication;

public class Db {
    Connection prod(String url, String user) throws Exception {
        return DriverManager.getConnection(url, user, System.getenv("DB_PASSWORD"));
    }

    Connection memory() throws Exception {
        return DriverManager.getConnection("jdbc:h2:mem:reports", "sa", "");
    }

    Connection withProps(String url, java.util.Properties props) throws Exception {
        return DriverManager.getConnection(url, props);
    }

    PasswordAuthentication auth(String user, char[] secret) {
        return new PasswordAuthentication(user, secret);
    }
}
