package com.acme.api;

import java.io.IOException;

public interface Importer {
~>    void importAll(String source) throws IOException, Exception;

~>    <T> T parse(byte[] raw, Class<T> type) throws Exception;
}
