package app;

import java.io.Console;

public class Login {
    public static void main(String[] args) {
        Console console = System.console();
        String user = console.readLine("User: ");
~>        String password = new String(console.readPassword("Password: "));
        authenticate(user, password);
    }
    static void authenticate(String u, String p) {}
}
