package com.acme;

import java.sql.Connection;
import java.sql.DriverManager;

public class Db {
    public Connection open(String user, String pass) throws Exception {
~>        return DriverManager.getConnection("jdbc:mysql://10.12.0.7:3306/orders", user, pass);
    }
}
