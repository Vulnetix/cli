package app;

public class Seed {
    void seed() {
        String username = "admin";
~>        String password = "admin";
        repo.save(new Account(username, password));
    }
}
