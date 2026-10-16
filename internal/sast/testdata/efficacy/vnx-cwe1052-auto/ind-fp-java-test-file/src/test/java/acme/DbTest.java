package acme;

public class DbTest {
    void t() throws Exception {
        java.sql.DriverManager.getConnection("jdbc:mysql://10.0.4.12:3306/orders", "u", "p");
    }
}
