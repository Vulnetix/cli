package com.acme.web;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class SignatureServlet extends HttpServlet {

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        PrintWriter writer = response.getWriter();
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(System.getenv("SIGNING_KEY").getBytes(), "HmacSHA256"));
            writer.print(java.util.HexFormat.of().formatHex(mac.doFinal(request.getInputStream().readAllBytes())));
        } catch (NoSuchAlgorithmException
                | InvalidKeyException problem) {
~>            problem.printStackTrace(response.getWriter());
~>            writer.print(problem);
        }
    }
}
