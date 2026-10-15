package app;

public class Login {
    static final String PASSWORD_FIELD = "password";
    static final String PASSWORD_PARAM = "admin";
    String passwordLabel = "Password";

    boolean check(String password) {
        return !"changeme".equals(password);
    }
}
