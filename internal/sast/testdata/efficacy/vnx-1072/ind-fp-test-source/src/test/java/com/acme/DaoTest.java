package com.acme;
import java.sql.*;
public class DaoTest {
    void t() throws Exception {
        Connection c = DriverManager.getConnection("jdbc:h2:mem:t");
        org.springframework.jdbc.datasource.DriverManagerDataSource ds = new org.springframework.jdbc.datasource.DriverManagerDataSource();
    }
}
