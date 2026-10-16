package com.acme;

import java.io.File;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import javax.servlet.http.HttpServletRequest;

class DownloadServletTest {
    @Test
    void readsFile() {
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        String name = request.getParameter("file");
        File f = new File("/tmp/fixtures", "sample.txt");
    }
}
