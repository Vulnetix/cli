package app;

public class TokenCheck {
    public boolean isTokenValid(String token) {
        try {
            Signer.verify(token);
            return true;
        } catch (Exception e) {
~>            return true;
        }
    }
}
