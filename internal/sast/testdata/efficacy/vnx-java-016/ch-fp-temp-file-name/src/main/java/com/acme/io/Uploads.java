package com.acme.io;

import java.io.File;
import @@sample:o[r]g[.][a]pa[c]he[.]co[m]mo[n]s[.][l]an[g]3[.][R]an[d]om[S]tr[i]ng[U]ti[l]s@@;

public class Uploads {
    public File tempFile(File dir) {
        String tmpName = "upload-" + RandomStringUtils.randomAlphanumeric(8) + ".tmp";
        return new File(dir, tmpName);
    }
}
