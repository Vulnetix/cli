package com.acme.jobs;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class JobLock {
    public void acquire(long pid) throws IOException {
~>        Path lock = Paths.get(System.getProperty("java.io.tmpdir"), "acme-job.lock");
        Files.write(lock, Long.toString(pid).getBytes(@@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@));
    }
}
