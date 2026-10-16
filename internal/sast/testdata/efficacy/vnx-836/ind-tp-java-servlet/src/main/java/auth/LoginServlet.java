package auth;

public class LoginServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        User user = users.find(request.getParameter("user"));
        String presented = request.getParameter("hash");
~>        if (MessageDigest.isEqual(user.getPasswordHash().getBytes(), presented.getBytes())) {
            session.setAttribute("user", user);
        }
    }
}
