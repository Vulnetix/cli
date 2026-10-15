package app;

public class TokenGuard {
    public boolean validateToken(String token) {
        try {
            parser.parse(token);
        } catch (JwtException e) {
            throw new AccessDeniedException("invalid token", e);
        }
        return true;
    }

    public boolean isRetryable(Exception ex) {
        try {
            classify(ex);
        } catch (Exception e) {
            return true;
        }
        return false;
    }
}
