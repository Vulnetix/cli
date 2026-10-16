package app;

public class Auth {
    boolean isAdmin(String role, String status) {
        if ("admin" == role) {
            return true;
        }
        return status != "DISABLED";
    }
}
