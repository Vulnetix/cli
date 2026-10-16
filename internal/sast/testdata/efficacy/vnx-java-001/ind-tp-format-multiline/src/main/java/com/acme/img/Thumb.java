package com.acme.img;

import java.io.IOException;
import javax.servlet.http.HttpServletRequest;

public class Thumb {
    public void make(HttpServletRequest req) throws IOException {
        String name = req.getParameter("file");
        Runtime rt = Runtime.getRuntime();
~>        rt.exec(
            String.format("convert uploads/%s -resize 64x64 thumbs/%s.png", name, name));
    }
}
