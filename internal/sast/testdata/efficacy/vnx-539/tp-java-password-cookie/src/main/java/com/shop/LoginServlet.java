public class LoginServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) {
        String password = request.getParameter("password");
        Cookie remember = new Cookie("password", password);
~>        remember.setMaxAge(60 * 60 * 24 * 30);
        response.addCookie(remember);
    }
}
