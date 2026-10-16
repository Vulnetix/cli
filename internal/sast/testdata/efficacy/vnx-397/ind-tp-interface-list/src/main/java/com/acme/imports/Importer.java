package com.acme.imports;

import java.io.IOException;

public interface Importer {
~>    void importAll(String source) throws IOException, Exception;

    int pending();
}
