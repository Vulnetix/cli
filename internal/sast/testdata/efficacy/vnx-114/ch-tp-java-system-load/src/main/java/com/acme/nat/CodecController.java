package com.acme.nat;

import java.net.URL;
import java.net.URLClassLoader;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CodecController {

    @GetMapping("/codec")
    public String codec(@RequestParam String codec) {
        String libPath = "/opt/codecs/" + codec + ".so";
~>        System.load(libPath);
        return "loaded";
    }

    @GetMapping("/extension")
    public String extension(@RequestParam("jar") String jarUrl) throws Exception {
~>        try (URLClassLoader cl = new URLClassLoader(new URL[] { new URL(jarUrl) })) {
            return cl.loadClass("com.acme.Ext").getName();
        }
    }
}
