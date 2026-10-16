package acme;

import java.sql.*;

public class Db {
    public Connection open(String user, String secret) throws SQLException {
~>        return DriverManager.getConnection("jdbc:postgresql://pg01.prod.acme.io:5432/orders", user, secret);
    }
}
