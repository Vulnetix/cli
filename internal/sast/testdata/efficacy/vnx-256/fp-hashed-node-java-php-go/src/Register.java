package app;

public class Register {
    void post(HttpServletRequest request) {
        user.setPassword(passwordEncoder.encode(request.getParameter("password")));
        String raw = request.getParameter("password");
        String digest = BCrypt.hashpw(raw, BCrypt.gensalt());
        user.setPassword(digest);
    }
}
