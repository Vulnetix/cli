package app;

public class RegisterServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) {
        User user = new User();
        user.setUsername(request.getParameter("username"));
~>        user.setPassword(request.getParameter("password"));
        userRepository.save(user);
        String pwd = request.getParameter("pwd");
~>        Cookie c = new Cookie("password", pwd);
        response.addCookie(c);
    }
}
