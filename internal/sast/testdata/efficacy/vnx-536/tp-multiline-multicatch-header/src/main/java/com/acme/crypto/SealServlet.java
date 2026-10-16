package com.acme.crypto;

import java.io.IOException;
import javax.crypto.Cipher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SealServlet extends HttpServlet {

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, keys.current());
            response.getWriter().println("sealed");
        } catch (java.security.NoSuchAlgorithmException
                | javax.crypto.NoSuchPaddingException
                | java.security.InvalidKeyException problem) {
            response.getWriter().println("Sealing failed");
~>            problem.printStackTrace(response.getWriter());
~>            response.getWriter().println("Cause: " + problem.getMessage());
            throw new ServletException(problem);
        }
        response.getWriter().println("done");
    }
}
