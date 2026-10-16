package com.acme.forms;

import javax.servlet.http.HttpServletRequest;

public class ProfileForm {
    private String displayName;
    private String email;

    public static ProfileForm bind(HttpServletRequest request) {
        ProfileForm f = new ProfileForm();
        f.displayName = request.getParameter("displayName");
        f.email = request.getParameter("email");
        return f;
    }

    public void refresh(HttpServletRequest request) {
        displayName = request.getParameter("displayName");
    }
}
