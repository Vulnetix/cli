package com.acme.web;

import java.io.IOException;
import java.util.Map;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

public class GuardedRedirects {
    private static final Map<Integer, String> DESTINATIONS = Map.of(1, "/welcome", 2, "/login");
    private static final Set<String> ALLOWED = Set.of("https://partner.example/");

    public ModelAndView safe(@RequestParam(name = "destId", defaultValue = "1") Integer destId) {
        String dest = DESTINATIONS.getOrDefault(destId, "/welcome");
        return new ModelAndView("redirect:" + dest);
    }

    public void checked(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String next = request.getParameter("next");
        if (next == null || !next.startsWith("/") || next.startsWith("//")) {
            next = "/";
        }
        response.sendRedirect(next);

        String partner = request.getParameter("partner");
        if (ALLOWED.contains(partner)) {
            response.sendRedirect(partner);
        }
    }
}
