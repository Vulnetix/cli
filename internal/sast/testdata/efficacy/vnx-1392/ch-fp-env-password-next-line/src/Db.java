package shop;

import java.sql.Connection;
import java.sql.DriverManager;

public class Db {
    Connection open() throws Exception {
        String user = "postgres";
        String password = System.getenv("PGPASSWORD");
        return DriverManager.getConnection("jdbc:postgresql://db/shop", user, password);
    }
}
