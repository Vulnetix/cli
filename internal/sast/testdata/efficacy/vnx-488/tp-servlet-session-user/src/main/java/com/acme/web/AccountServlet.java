package com.acme.web;

public class AccountServlet extends HttpServlet {
	User user;

	protected void doPost(HttpServletRequest req, HttpServletResponse resp) {
~>		user = (User) req.getSession().getAttribute("user");
		resp.getWriter().write(user.getEmail());
	}
}
