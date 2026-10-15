package com.acme.ext;

import java.net.URL;
import java.net.URLClassLoader;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class NativeController {
    @PostMapping("/native")
    public String load(@RequestParam String lib, javax.servlet.http.HttpServletRequest request) throws Exception {
~>        System.loadLibrary(lib);
~>        System.load(request.getParameter("path"));
        String jar = request.getParameter("jar");
~>        URLClassLoader cl = new URLClassLoader(new URL[] { new URL(jar) });
        return "ok";
    }
}
