package com.example.sync;

import java.io.File;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;

public class Mirror {
    public String manifest(URL remote) throws Exception {
~>        return IOUtils.toString(remote, @@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@);
    }

    public void pull(URL remote, File dest) throws Exception {
~>        FileUtils.copyURLToFile(remote, dest);
    }
}
