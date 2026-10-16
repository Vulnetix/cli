package app;

import javax.servlet.http.HttpServletRequest;

class Cap {
    static final int MAX = 1000;

    int sum(HttpServletRequest request) {
        int n = Integer.parseInt(request.getParameter("n"));
        int total = 0;
        for (int i = 0; i < n && i < MAX; i++) {
            total += i;
        }
        return total;
    }
}
