package auth;

public class Verify {
    boolean ok(HttpServletRequest request, User user) {
        String candidate = request.getParameter("password");
        return encoder.matches(candidate, user.getPasswordHash());
    }

    boolean same(User a, User b) {
        return a.getPasswordHash().equals(b.getPasswordHash());
    }
}
