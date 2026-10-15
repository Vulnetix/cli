package app

import jakarta.servlet.http.Cookie
import jakarta.servlet.http.HttpServletResponse

class LoginController {
    fun onLogin(user: User, response: HttpServletResponse) {
~>        val flag = Cookie("isAdmin", user.admin.toString())
        flag.path = "/"
        response.addCookie(flag)
    }
}
