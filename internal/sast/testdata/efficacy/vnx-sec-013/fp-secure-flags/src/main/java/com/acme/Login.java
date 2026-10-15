public class Login {
    public void login(HttpServletResponse response, String token) {
        Cookie cookie = new Cookie("SESSION", token);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        response.addCookie(cookie);
    }
}
