package com.shop;

import com.sun.jna.Native;
import groovy.lang.GroovyShell;
import java.io.File;
import org.springframework.web.bind.annotation.*;

@RestController
public class Plugins {
    private final GroovyShell shell = new GroovyShell();

    @GetMapping("/macro/{name}")
    public Object macro(@PathVariable String name) throws Exception {
~>      return shell.evaluate(new File("/opt/macros/" + name + ".groovy"));
    }

    @GetMapping("/codec")
    public void codec(@RequestParam String lib) {
~>      Native.load(lib, Object.class);
    }
}
