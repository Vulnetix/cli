package com.acme;

import java.io.*;
import java.util.jar.*;

public class JarUnpack {
    public void unpack(File jar, String outDir) throws IOException {
        try (JarInputStream jis = new JarInputStream(new FileInputStream(jar))) {
            JarEntry je;
            while ((je = jis.getNextJarEntry()) != null) {
                String name = je.getName();
~>                FileOutputStream fos = new FileOutputStream(outDir + File.separator + name);
                jis.transferTo(fos);
                fos.close();
            }
        }
    }
}
