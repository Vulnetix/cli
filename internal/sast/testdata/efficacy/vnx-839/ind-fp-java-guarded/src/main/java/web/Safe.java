package web;

public class Safe {
    String a(HttpServletRequest request) {
        int n = Integer.parseInt(request.getParameter("page"));
        if (n >= 0 && n < pages.size()) {
            return pages.get(n);
        }
        return null;
    }

    String b(HttpServletRequest request) {
        int n = Math.max(0, Integer.parseInt(request.getParameter("page")));
        if (n < pages.size()) {
            return pages.get(n);
        }
        return null;
    }
}
