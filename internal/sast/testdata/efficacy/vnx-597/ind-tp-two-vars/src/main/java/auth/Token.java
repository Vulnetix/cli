package auth;

public class Token {
    boolean check(String presented, String expectedToken) {
~>        return presented == expectedToken;
    }
}
