package app;

public class Account {
    private String password;

    public String getPassword() { return password; }

    boolean same(Account other) {
        String a = new String(other.getPassword());
        String label = String.valueOf(count);
        return a.equals(label);
    }
}
