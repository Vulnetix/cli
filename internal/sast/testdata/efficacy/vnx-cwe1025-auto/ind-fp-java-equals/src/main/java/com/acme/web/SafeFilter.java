package com.acme.web;

import java.util.Objects;
import javax.servlet.http.HttpServletRequest;

public class SafeFilter {
    private enum Mode { READ, WRITE }
    public boolean check(HttpServletRequest request, String expected, Mode m, int a, int b) {
        boolean x = "admin".equals(request.getParameter("role"));
        boolean y = Objects.equals(request.getParameter("mode"), expected);
        boolean z = m == Mode.READ && a == b;
        boolean n = request.getAttribute("user") != null;
        char c = expected.charAt(0);
        return x && y && z && n && c == 'a' && request.getClass() == SafeFilter.class;
    }
}
