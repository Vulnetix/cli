public class LogoutServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        Cookie gone = new Cookie("password", "");
        gone.setMaxAge(0);
        response.addCookie(gone);
    }
}
