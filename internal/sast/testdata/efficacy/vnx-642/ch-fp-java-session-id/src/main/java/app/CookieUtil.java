package app;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

public class CookieUtil {
    public static Cookie sessionCookie(String id) {
        Cookie c = new Cookie("JSESSIONID", id);
        c.setHttpOnly(true);
        c.setSecure(true);
        return c;
    }

    public static String theme(HttpServletRequest req) {
        for (Cookie c : req.getCookies()) {
            if (c.getName().equals("admin_theme")) {
                return c.getValue();
            }
        }
        return "light";
    }
}
