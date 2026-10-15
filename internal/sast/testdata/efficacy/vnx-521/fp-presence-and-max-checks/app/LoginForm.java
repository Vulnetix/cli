package app;

public class LoginForm {
    public boolean valid(String password, String username) {
        if (password.length() < 1) {
            return false;
        }
        if (password.length() > 30 || username.length() < 3) {
            return false;
        }
        return password.length() <= 128;
    }
}
