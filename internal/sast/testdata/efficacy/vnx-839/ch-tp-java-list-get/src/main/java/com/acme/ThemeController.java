package com.acme;

import java.util.List;
import javax.servlet.http.HttpServletRequest;

public class ThemeController {
    private final List<String> themes = List.of("light", "dark", "contrast");

    public String pick(HttpServletRequest request) {
        int choice = Integer.parseInt(request.getParameter("theme"));
~>        if (choice >= themes.size()) {
            return themes.get(0);
        }
        return themes.get(choice);
    }
}
