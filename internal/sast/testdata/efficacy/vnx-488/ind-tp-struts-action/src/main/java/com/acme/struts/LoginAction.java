package com.acme.struts;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.struts.action.Action;
import org.apache.struts.action.ActionForm;
import org.apache.struts.action.ActionForward;
import org.apache.struts.action.ActionMapping;

public class LoginAction extends Action {
    private String username;

    @Override
    public ActionForward execute(ActionMapping mapping, ActionForm form,
                                 HttpServletRequest request, HttpServletResponse response) {
~>        username = request.getParameter("username");
        if (auth.check(username, request.getParameter("password"))) {
            return mapping.findForward("success");
        }
        return mapping.findForward("failure");
    }
}
