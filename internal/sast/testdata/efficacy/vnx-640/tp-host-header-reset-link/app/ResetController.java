package app;

public class ResetController {
    public String sendPasswordResetLink(String email, HttpServletRequest request) {
        String resetLink = tokens.issue(email);
~>        String host = request.getHeader("Host");
        mail.send(email, "http://" + host + "/reset/" + resetLink);
        return "ok";
    }
}
