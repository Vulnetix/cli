package com.acme.boot;

import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.SQLException;

public class Drivers {
    public void register(Driver d) throws SQLException {
        DriverManager.registerDriver(d);
        DriverManager.setLoginTimeout(5);
        Driver found = DriverManager.getDriver("jdbc:postgresql://db/app");
        System.out.println("DriverManager.getConnection is not used here " + found);
    }
}
