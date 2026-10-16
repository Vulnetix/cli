package app;

public class Auth {
    /**
     * Logs a user in.
     * @param password the user's password
     * @param token the access token returned by the IdP
     */
    void login(String user, String password, String token) {}

    // password: must be at least 12 characters
    // token = refresh token lifetime is 30 days
}
